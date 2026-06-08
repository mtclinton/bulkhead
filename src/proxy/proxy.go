//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// "CONNECT " (8) + host (<=253) + ":" (1) + port (<=5) + slack. A request longer
	// than this is rejected outright rather than parsed.
	maxRequestLen  = 300
	requestTimeout = 5 * time.Second // budget to send the one request line / read the reply
	dialTimeout    = 10 * time.Second
	maxConcurrent  = 256
)

// Proxy mediates every agent egress flow. One instance serves all agents on the socket.
type Proxy struct {
	allow  *Allowlist
	dialer *net.Dialer
	sem    chan struct{} // bounds concurrent upstream connections
}

func NewProxy(a *Allowlist) *Proxy {
	return &Proxy{
		allow:  a,
		dialer: &net.Dialer{Timeout: dialTimeout},
		sem:    make(chan struct{}, maxConcurrent),
	}
}

// handleConn services one agent connection: read the single CONNECT request, check the
// allowlist, resolve + dial on the host, reply, then splice. Every terminal path logs.
func (p *Proxy) handleConn(c net.Conn) {
	defer c.Close()

	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	default:
		logd("REJECT", "", "", "at capacity")
		writeReply(c, "ERR busy")
		return
	}

	_ = c.SetReadDeadline(time.Now().Add(requestTimeout))
	host, port, err := readRequest(c)
	if err != nil {
		logd("REJECT", "", "", err.Error())
		writeReply(c, "ERR badrequest")
		return
	}
	if !p.allow.Allows(host) {
		logd("DENY", host, port, "not in allowlist")
		writeReply(c, "ERR denied")
		return
	}

	// Resolve + connect on the HOST (the guest has no resolver). The destination is the
	// exact (host, port) the allowlist just approved — one parse, no second interpretation.
	_ = c.SetReadDeadline(time.Time{})
	up, err := p.dialer.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		logd("DIALFAIL", host, port, err.Error())
		writeReply(c, "ERR upstream")
		return
	}
	defer up.Close()

	logd("ALLOW", host, port, up.RemoteAddr().String())
	if err := writeReply(c, "OK"); err != nil {
		return
	}
	splice(c, up)
}

// readRequest reads exactly one line — "CONNECT host:port\n" — directly off the
// connection (unbuffered, so the agent's subsequent bytes, e.g. a TLS ClientHello, are
// left intact for the splice). The returned (host, port) is the SINGLE parse of the
// destination, shared by the allowlist check and the dial; there is no second parse
// anywhere, which is what forecloses the endsWith/getaddrinfo differential class. Any
// control byte (NUL, CR, TAB, ...) before the terminating '\n' is rejected.
func readRequest(c net.Conn) (host, port string, err error) {
	line, err := readLine(c, maxRequestLen)
	if err != nil {
		return "", "", err
	}
	for i := 0; i < len(line); i++ {
		if line[i] < 0x20 || line[i] == 0x7f {
			return "", "", fmt.Errorf("control byte 0x%02x in request", line[i])
		}
	}
	const pfx = "CONNECT "
	if !strings.HasPrefix(line, pfx) {
		return "", "", errors.New("malformed request (want CONNECT host:port)")
	}
	host, port, err = net.SplitHostPort(strings.TrimPrefix(line, pfx))
	if err != nil {
		return "", "", fmt.Errorf("bad host:port: %w", err)
	}
	if err := validateHost(host); err != nil {
		return "", "", err
	}
	if err := validatePort(port); err != nil {
		return "", "", err
	}
	return host, port, nil
}

// readLine reads bytes until '\n' (excluded) or max bytes. Reading one byte at a time
// keeps the proxy from swallowing any payload past the request line, so the raw stream
// stays intact for splicing.
func readLine(c net.Conn, max int) (string, error) {
	buf := make([]byte, 0, 64)
	var one [1]byte
	for len(buf) < max {
		n, err := c.Read(one[:])
		if n == 1 {
			if one[0] == '\n' {
				return string(buf), nil
			}
			buf = append(buf, one[0])
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("request line too long")
}

// validateHost accepts an IP literal or a syntactically valid DNS name. It is deliberately
// strict (RFC-1123 label charset, length caps) so a hostile host string can carry nothing
// but a name — no embedded delimiters for a downstream parser to disagree about.
func validateHost(h string) error {
	if h == "" {
		return errors.New("empty host")
	}
	if net.ParseIP(h) != nil {
		return nil // IP literal
	}
	if len(h) > 253 {
		return errors.New("host too long")
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("bad DNS label length")
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			ok := ch == '-' ||
				(ch >= '0' && ch <= '9') ||
				(ch >= 'a' && ch <= 'z') ||
				(ch >= 'A' && ch <= 'Z')
			if !ok {
				return fmt.Errorf("illegal char %q in host", ch)
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("label has leading/trailing hyphen")
		}
	}
	return nil
}

func validatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("bad port %q", p)
	}
	return nil
}

func writeReply(c net.Conn, msg string) error {
	_ = c.SetWriteDeadline(time.Now().Add(requestTimeout))
	_, err := io.WriteString(c, msg+"\n")
	_ = c.SetWriteDeadline(time.Time{})
	return err
}

// splice copies bytes both ways until both halves hit EOF, half-closing each write end
// so a one-way shutdown (e.g. TLS close-notify) propagates instead of wedging the peer.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite() // both *net.UnixConn and *net.TCPConn implement this
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

func logd(action, host, port, detail string) {
	if host == "" {
		log.Printf("egress %s: %s", action, detail)
		return
	}
	log.Printf("egress %s: %s:%s %s", action, host, port, detail)
}
