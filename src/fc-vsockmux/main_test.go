//go:build linux

package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestFileConnDeadline: the non-blocking fd fix — SetReadDeadline must actually WORK on a fileConn (over a
// poller-adopted non-blocking socket), so a read against a silent peer TIMES OUT instead of blocking
// forever. A blocking fd (the bug) made deadlines inert ("file type does not support deadline").
func TestFileConnDeadline(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(fds[0], true); err != nil { // mirror vsockDial's SetNonblock-before-NewFile
		t.Fatal(err)
	}
	fc := &fileConn{f: os.NewFile(uintptr(fds[0]), "sp")}
	defer fc.Close()
	defer syscall.Close(fds[1])
	if err := fc.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline must work on a non-blocking poller-adopted fd: %v", err)
	}
	start := time.Now()
	if _, err := fc.Read(make([]byte, 8)); err == nil || !os.IsTimeout(err) { // peer never writes
		t.Fatalf("read should time out (deadline working), got err=%v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("read blocked far past the deadline")
	}
}

// TestSpliceIdleTeardown is the DoS-fix regression: a spliced connection that goes SILENT (both peers
// connect but never send and never close) must be torn down within idleTimeout so its per-leg conn-cap slot
// is released — before the fix splice's deadline-less io.Copy blocked forever and pinned the slot, turning
// the cap into a self-inflicted DoS.
func TestSpliceIdleTeardown(t *testing.T) {
	old := idleTimeout
	idleTimeout = 200 * time.Millisecond
	defer func() { idleTimeout = old }()
	dir := t.TempDir()
	aHost, aPeer := unixPair(t, filepath.Join(dir, "a.sock"))
	bHost, bPeer := unixPair(t, filepath.Join(dir, "b.sock"))
	defer aPeer.Close()
	defer bPeer.Close()
	done := make(chan struct{})
	go func() { splice(aHost, bHost); close(done) }() // both directions idle -> must return
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("splice did NOT tear down a silent connection within the idle timeout (the slot would be pinned forever)")
	}
}

// TestSpliceHalfClose: splice must move bytes BOTH ways and, when one side finishes writing (CloseWrite),
// propagate that EOF to the peer WITHOUT tearing down the other direction — so the proxy's OK/relay or the
// router's HTTP response can't be truncated by a naive close-both-on-first-EOF (the adversarial half-close
// must-fix). Uses a real UNIX socketpair (which has CloseWrite, like the production legs).
func TestSpliceHalfClose(t *testing.T) {
	dir := t.TempDir()
	// two independent UNIX socketpairs; splice bridges one end of each.
	aHost, aPeer := unixPair(t, filepath.Join(dir, "a.sock"))
	bHost, bPeer := unixPair(t, filepath.Join(dir, "b.sock"))
	go splice(aHost, bHost)

	// aPeer -> (splice) -> bPeer
	if _, err := aPeer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	aPeer.(*net.UnixConn).CloseWrite() // half-close the a->b direction only
	if got := readN(t, bPeer, 4); got != "ping" {
		t.Fatalf("a->b: got %q want ping", got)
	}
	// the b->a direction must STILL be open after a's half-close (no truncation).
	if _, err := bPeer.Write([]byte("pong")); err != nil {
		t.Fatalf("b->a after a half-close must still work: %v", err)
	}
	bPeer.(*net.UnixConn).CloseWrite()
	if got := readN(t, aPeer, 4); got != "pong" {
		t.Fatalf("b->a: got %q want pong", got)
	}
}

// TestListenLegRefusesSymlink: the leg path must NOT be bound if it is a pre-existing symlink — the
// load-bearing channel-confusion control (a post-escape attacker at the Firecracker uid must not be able
// to pre-plant a symlink that redirects a leg to another host socket).
func TestListenLegRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	// a fresh path binds fine.
	ln, err := listenLegFresh(filepath.Join(dir, "leg_2222"))
	if err != nil {
		t.Fatalf("fresh leg must bind: %v", err)
	}
	ln.Close()

	// a symlink at the leg path must be REFUSED (not followed).
	victim := filepath.Join(dir, "victim.sock")
	link := filepath.Join(dir, "leg_2223")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if _, err := listenLegFresh(link); err == nil {
		t.Fatal("listenLegFresh MUST refuse a symlink leg path (redirect attack), but it bound")
	}

	// a non-socket regular file at the leg path is also refused.
	reg := filepath.Join(dir, "leg_2224")
	os.WriteFile(reg, []byte("x"), 0o600)
	if _, err := listenLegFresh(reg); err == nil {
		t.Fatal("listenLegFresh MUST refuse a non-socket leg path, but it bound")
	}
}

// --- helpers ---

func unixPair(t *testing.T, path string) (host, peer net.Conn) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	peer, err = net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	host = <-ch
	if host == nil {
		t.Fatal("accept failed")
	}
	return host, peer
}

func readN(t *testing.T, c net.Conn, n int) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("readN: %v", err)
	}
	return string(buf)
}
