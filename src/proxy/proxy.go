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
	"syscall"
	"time"
)

const (
	// "CONNECT " (8) + host (<=253) + ":" (1) + port (<=5) + slack. A request longer
	// than this is rejected outright rather than parsed.
	maxRequestLen  = 300
	requestTimeout = 5 * time.Second // budget to send the one request line / read the reply
	dialTimeout    = 10 * time.Second
	maxConcurrent  = 256
	// A spliced tunnel idle (no bytes either direction) this long is reclaimed; tunnelMax
	// is the absolute per-tunnel cap (backstop against a slow-drip that refreshes the idle
	// timer forever). Together they bound how long one flow can pin a concurrency slot.
	idleTimeout = 120 * time.Second
	tunnelMax   = time.Hour
)

// Proxy mediates every agent egress flow. One instance serves all agents on the socket.
type Proxy struct {
	allow       *Allowlist
	dialer      *net.Dialer
	sem         chan struct{} // bounds concurrent upstream connections
	idleTimeout time.Duration
	tunnelMax   time.Duration
}

// NewProxy builds the proxy. internalCIDRs are the ONLY internal (loopback / private /
// link-local / CGNAT / ...) destinations permitted; every other internal address is
// denied at dial time via dialer.Control — enforced on the ACTUAL resolved address, so
// an allowlisted NAME that resolves (or is DNS-rebound) to 127.0.0.1, the 169.254.169.254
// metadata endpoint, or an RFC-1918 host cannot be reached through the mediated path.
// An empty list (the default) denies all internal classes: only global-unicast egress.
func NewProxy(a *Allowlist, internalCIDRs []*net.IPNet) *Proxy {
	d := &net.Dialer{Timeout: dialTimeout}
	d.Control = func(_, address string, _ syscall.RawConn) error {
		return checkDialAddr(address, internalCIDRs)
	}
	return &Proxy{
		allow:       a,
		dialer:      d,
		sem:         make(chan struct{}, maxConcurrent),
		idleTimeout: idleTimeout,
		tunnelMax:   tunnelMax,
	}
}

// checkDialAddr runs in dialer.Control on the resolved remote address (covering the
// resolve-at-dial / rebinding window). It denies internal address classes unless the
// operator opted that CIDR in — the SSRF / metadata guard for the mediated egress path.
func checkDialAddr(address string, allow []*net.IPNet) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("egress: unparseable dial address %q", address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("egress: non-IP dial address %q", host)
	}
	for _, n := range allow {
		if n.Contains(ip) {
			return nil // operator-permitted internal destination
		}
	}
	if isInternalIP(ip) {
		return fmt.Errorf("egress: destination %s is an internal address (denied)", ip)
	}
	return nil
}

// isInternalIP reports whether ip is in a class the agent must not reach by default.
// The stdlib predicates consult To4(), so v4-mapped IPv6 (::ffff:127.0.0.1) is covered;
// 100.64/10 CGNAT is not an IsPrivate range, so it is checked explicitly.
func isInternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return true // 100.64.0.0/10 (CGNAT / tailnet)
	}
	return false
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
	p.splice(c, up)
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
		return nil // canonical IP literal
	}
	// Reject ambiguous numeric IPv4 aliases that net.ParseIP rejects but a libc resolver
	// (getaddrinfo) would coerce to an address — 2130706433, 0x7f000001, 0177.0.0.1, 127.1,
	// 127.0.0.01 all collapse to 127.0.0.1. Classifying these as DNS names would reintroduce
	// the policy-vs-resolver differential this proxy exists to foreclose, so they are refused.
	if isNumericAlias(h) {
		return fmt.Errorf("ambiguous numeric host %q", h)
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

// isNumericAlias reports whether h looks like a non-canonical numeric IPv4 address
// (which it must, since net.ParseIP already rejected it) rather than a real DNS name:
// composed solely of digits and dots, or a hex literal (0x...).
func isNumericAlias(h string) bool {
	if strings.HasPrefix(h, "0x") || strings.HasPrefix(h, "0X") {
		return true
	}
	for i := 0; i < len(h); i++ {
		if (h[i] < '0' || h[i] > '9') && h[i] != '.' {
			return false
		}
	}
	return true // all digits and dots, yet not a canonical IP
}

// splice copies bytes both ways until EOF, error, a per-direction idle timeout, or the
// absolute tunnel cap — bounding how long one flow can pin a concurrency slot (a silent
// or stuck tunnel is reclaimed within idleTimeout; a slow-drip within tunnelMax). The
// write half is closed on each direction's EOF so a legitimate half-close (request sent,
// response still pending) is preserved — the other direction keeps its own idle bound.
func (p *Proxy) splice(a, b net.Conn) {
	deadline := time.Now().Add(p.tunnelMax)
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			now := time.Now()
			if !now.Before(deadline) {
				break // absolute tunnel cap
			}
			rd := now.Add(p.idleTimeout)
			if rd.After(deadline) {
				rd = deadline
			}
			_ = src.SetReadDeadline(rd)
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break // EOF, idle-timeout, or hard error
			}
		}
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
