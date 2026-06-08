package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeProxy listens on a UDS, consumes one CONNECT line, sends reply, and (on an OK reply)
// echoes whatever the client writes afterwards.
func fakeProxy(t *testing.T, reply string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := br.ReadString('\n'); err != nil { // consume CONNECT line
					return
				}
				io.WriteString(c, reply)
				if strings.HasPrefix(reply, "OK") {
					io.Copy(c, br) // echo the tunnel payload
				}
			}()
		}
	}()
	return sock
}

func TestProxyDialAllowEcho(t *testing.T) {
	conn, err := proxyDial(context.Background(), fakeProxy(t, "OK\n"), "example.com:443")
	if err != nil {
		t.Fatalf("proxyDial: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "hello")
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
		t.Fatalf("tunnel echo: %q %v", got, err)
	}
}

func TestProxyDialDenied(t *testing.T) {
	_, err := proxyDial(context.Background(), fakeProxy(t, "ERR denied\n"), "blocked.example:80")
	if !errors.Is(err, errEgressDenied) {
		t.Fatalf("want errEgressDenied, got %v", err)
	}
}

func TestProxyDialOtherErr(t *testing.T) {
	_, err := proxyDial(context.Background(), fakeProxy(t, "ERR upstream\n"), "x:80")
	if err == nil || errors.Is(err, errEgressDenied) {
		t.Fatalf("want a generic transport error, got %v", err)
	}
}

// With BULKHEAD_EGRESS_SOCK set, the web-fetch client tunnels a real GET through the proxy.
func TestEgressClientThroughProxy(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				line, _ := br.ReadString('\n')
				if !strings.HasPrefix(line, "CONNECT example.com:80") {
					io.WriteString(c, "ERR badrequest\n")
					return
				}
				io.WriteString(c, "OK\n")
				for { // drain the HTTP request head
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				io.WriteString(c, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi")
			}()
		}
	}()
	t.Setenv("BULKHEAD_EGRESS_SOCK", sock)
	resp, err := egressClient(5 * time.Second).Get("http://example.com/")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
