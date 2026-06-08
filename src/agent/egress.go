package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ADR-0034 mediated egress. A jailed agent runs in a no-route network namespace with two
// bind-mounted unix sockets and nothing else: the router UDS (trusted model calls) and the
// egress-proxy UDS (untrusted outbound web). Both legs gate on an env var so dev/qemu/test
// keep the plain TCP path; only inside the jail are the sockets present.

// errEgressDenied is returned by the proxy dialer when the egress proxy refuses the
// destination, so the web-fetch tool can report a clean DENIED rather than a raw error.
var errEgressDenied = errors.New("egress denied by proxy")

// routerClient is the HTTP client for the model-router leg. With BULKHEAD_ROUTER_UDS set
// (the jail), it dials the router's unix socket regardless of the request URL host;
// otherwise it uses the normal TCP transport to BULKHEAD_ROUTER_URL.
func routerClient() *http.Client {
	if sock := os.Getenv("BULKHEAD_ROUTER_UDS"); sock != "" {
		return &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sock)
				},
			},
		}
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// egressClient is the HTTP client for the web-fetch tool. With BULKHEAD_EGRESS_SOCK set
// (the jail), every dial is tunneled through the host egress proxy via one CONNECT line;
// otherwise it dials directly (dev/qemu). TLS, when used, is negotiated end-to-end over
// the tunnel — the proxy sees only opaque bytes in increment 1.
func egressClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{}
	if sock := os.Getenv("BULKHEAD_EGRESS_SOCK"); sock != "" {
		tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return proxyDial(ctx, sock, addr)
		}
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// proxyDial opens a tunnel to addr (host:port) through the egress proxy at sock: it sends
// exactly one "CONNECT host:port\n" and, on "OK", returns the now-tunneled connection.
// "ERR denied" maps to errEgressDenied; any other reply is a transport error. The reply is
// read one byte at a time so no tunnel payload is consumed into a buffer.
func proxyDial(ctx context.Context, sock, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := fmt.Fprintf(c, "CONNECT %s\n", addr); err != nil {
		c.Close()
		return nil, err
	}
	reply, err := readReply(c, 256)
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{}) // hand a clean conn to http/TLS
	switch {
	case reply == "OK":
		return c, nil
	case strings.HasPrefix(reply, "ERR denied"):
		c.Close()
		return nil, errEgressDenied
	default:
		c.Close()
		return nil, fmt.Errorf("egress proxy: %s", reply)
	}
}

func readReply(c net.Conn, max int) (string, error) {
	buf := make([]byte, 0, 16)
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
	return "", errors.New("egress proxy reply too long")
}
