//go:build linux

// ADR-0042: the Firecracker hostile-tier mediated channel. An agent inside a Firecracker microVM has NO
// direct network (the per-instance VM config omits the virtio-net stanza entirely); its ONLY way out is
// the SAME mediated path the other tiers use — the host egress proxy and model router UNIX sockets, which
// enforce ADR-0034 policy and sign the audit chain. Firecracker's only host<->guest channel is virtio-vsock.
//
// bulkhead-fc-vsockmux is the small, transport-only "mediation fabric" that bridges that channel. It has
// no HTTP/CONNECT parsing and never derives a dial target from guest bytes — it is a byte-transparent
// splice, exactly like runsc's --host-uds=open legs, so the proxy/router parsers and their
// single-canonical-parse guarantee are unchanged. Modes:
//
//   serve-host <uds-base> <port>=<target-uds> ...   HOST side (the mux). For each guest vsock port P,
//       Firecracker (the vsock CLIENT for guest-initiated flows) connects INTO a host UNIX listener at
//       "<uds-base>_<P>"; the mux listens there and splices to the fixed, operator-supplied <target-uds>
//       (the real egress-proxy / router socket). The port->target table is set at launch, NEVER from the
//       guest. Load-bearing hygiene (the channel-confusion finding): the mux REFUSES to bind a leg path
//       that is a symlink or a non-socket (O_NOFOLLOW-equivalent), so a post-VMM-escape attacker at the
//       Firecracker uid cannot repoint a leg at an arbitrary host socket; the launcher gives it a fresh
//       0700 per-instance dir of which it is the sole writer. A per-instance concurrent-connection CAP
//       gives fail-closed backpressure so one compromised microVM cannot flood the shared proxy/router.
//
//   serve-guest <unix-path>=<port> ...              GUEST side (the in-VM forwarder, slice 2). Presents the
//       agent's expected UNIX leg paths and splices each accepted connection to AF_VSOCK(host, <port>) —
//       so the agent binary is UNCHANGED across tiers (it always net.Dial("unix", ...) its legs).
//
//   probe <cid> <port> ok|reset                     GUEST verifier (slice 1). AF_VSOCK-connects and either
//       round-trips a CONNECT line (ok) or asserts the connect is refused (reset) — proving the guest can
//       reach ONLY a provisioned port.
//   nonic                                           GUEST verifier: asserts there is no NIC/route (the
//       no-direct-network invariant's device-model half).
//   stub <uds>                                      TEST host endpoint: speaks the proxy CONNECT contract
//       (read a line, reply "OK\n") so slice 1 can prove the path without the real proxy.
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	afVSOCK        = 40 // AF_VSOCK
	vmaddrCIDHost  = 2  // VMADDR_CID_HOST — the guest always targets the host
	maxConnsPerLeg = 64 // per-leg concurrent-splice cap: fail-closed backpressure vs a flooding guest
)

// idle/total splice deadlines (vars so tests can shrink them). A spliced flow idle longer than idleTimeout
// OR open longer than tunnelMax is torn down — so a compromised guest that connects then goes silent (or
// holds its write side open after the peer half-closes) cannot pin a conn-cap slot forever and wedge the
// leg. Mirrors the egress proxy's idle/tunnel discipline.
var (
	idleTimeout = 120 * time.Second
	tunnelMax   = time.Hour
)

// sockaddrVM is the 16-byte struct sockaddr_vm (hand-built: stdlib syscall has no SockaddrVM, and we keep
// this binary stdlib-only / vendor-free so the guest forwarder stays minimal).
type sockaddrVM struct {
	Family   uint16
	Reserved uint16
	Port     uint32
	CID      uint32
	Zero     [4]byte
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "fc-vsockmux: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		die("usage: fc-vsockmux serve-host|serve-guest|probe|nonic|stub ...")
	}
	switch os.Args[1] {
	case "serve-host":
		serveHost(os.Args[2:])
	case "serve-guest":
		serveGuest(os.Args[2:])
	case "probe":
		probe(os.Args[2:])
	case "nonic":
		nonic()
	case "stub":
		stub(os.Args[2:])
	default:
		die("unknown mode %q", os.Args[1])
	}
}

// --- HOST mux: UNIX(<base>_<port>) -> dial(target UDS), byte-transparent splice ---

func serveHost(args []string) {
	if len(args) < 2 {
		die("usage: serve-host <uds-base> <port>=<target-uds> [...]")
	}
	base := args[0]
	var wg sync.WaitGroup
	for _, spec := range args[1:] {
		port, target, ok := strings.Cut(spec, "=")
		if !ok {
			die("bad port=target spec %q", spec)
		}
		legPath := base + "_" + port
		ln, err := listenLegFresh(legPath)
		if err != nil {
			die("%v", err)
		}
		fmt.Fprintf(os.Stderr, "fc-vsockmux: leg %s -> %s\n", legPath, target)
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem := make(chan struct{}, maxConnsPerLeg)
			for {
				c := acceptNext(ln)
				if c == nil {
					return
				}
				select {
				case sem <- struct{}{}: // slot acquired
				default:
					// at the per-leg cap: fail closed (drop) rather than pile onto the shared proxy/router.
					c.Close()
					continue
				}
				go func() {
					defer func() { <-sem }()
					up, err := net.DialTimeout("unix", target, 5*time.Second)
					if err != nil {
						c.Close()
						return
					}
					splice(c, up)
				}()
			}
		}(target)
	}
	wg.Wait()
}

// listenLegFresh binds the leg listener, REFUSING a pre-existing symlink or non-socket at the path
// (O_NOFOLLOW-equivalent: a post-escape attacker at the Firecracker uid must not be able to pre-plant a
// symlink that redirects the leg to another host socket). A stale socket from a crashed prior instance is
// removed first. The launcher owns the parent dir (0700, sole writer); this is defense at the bind itself.
func listenLegFresh(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to bind leg %s: it is a symlink (possible redirect attack)", path)
		}
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to bind leg %s: exists and is not a socket", path)
		}
		_ = os.Remove(path) // a stale socket from a prior crashed instance
	}
	return net.Listen("unix", path)
}

// acceptNext returns the next accepted conn, or nil when the listener is permanently closed (so the caller
// loop ends). A TRANSIENT accept error (EMFILE/ENFILE 'too many open files', ECONNABORTED, ...) is logged
// and retried after a short backoff — never a silent `return` that kills the leg forever while the process
// stays alive on its other legs (an unobservable loss of the mediated path).
func acceptNext(ln net.Listener) net.Conn {
	for {
		c, err := ln.Accept()
		if err == nil {
			return c
		}
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		log.Printf("fc-vsockmux: accept on %s: %v (retrying)", ln.Addr(), err)
		time.Sleep(50 * time.Millisecond)
	}
}

// --- GUEST forwarder (slice 2): UNIX leg path -> AF_VSOCK(host, port), byte-transparent splice ---

func serveGuest(args []string) {
	if len(args) < 1 {
		die("usage: serve-guest <unix-path>=<vsock-port> [...]")
	}
	var wg sync.WaitGroup
	for _, spec := range args {
		path, portStr, ok := strings.Cut(spec, "=")
		if !ok {
			die("bad path=port spec %q", spec)
		}
		port := mustPort(portStr)
		_ = os.Remove(path)
		ln, err := net.Listen("unix", path)
		if err != nil {
			die("listen %s: %v", path, err)
		}
		wg.Add(1)
		go func(port uint32) {
			defer wg.Done()
			for {
				c := acceptNext(ln)
				if c == nil {
					return
				}
				go func() {
					vf, err := vsockDial(vmaddrCIDHost, port)
					if err != nil {
						c.Close()
						return
					}
					splice(c, vf)
				}()
			}
		}(port)
	}
	wg.Wait()
}

// --- GUEST verifiers (slice 1) ---

func probe(args []string) {
	if len(args) != 3 {
		die("usage: probe <cid> <port> ok|reset")
	}
	cid := uint32(mustPort(args[0]))
	port := mustPort(args[1])
	want := args[2]
	conn, err := vsockDial(cid, port)
	switch want {
	case "reset":
		if err == nil {
			conn.Close()
			die("PROBE-FAIL: connect to (%d,%d) SUCCEEDED but a refusal was expected (unprovisioned port reachable!)", cid, port)
		}
		fmt.Printf("PROBE-OK: (%d,%d) refused as expected (%v)\n", cid, port, err)
	case "ok":
		if err != nil {
			die("PROBE-FAIL: connect to (%d,%d) failed: %v", cid, port, err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			die("PROBE-FAIL: vsock conn does not support a deadline (fd not poller-adopted): %v", err)
		}
		if _, err := conn.Write([]byte("CONNECT example.com:443\n")); err != nil {
			die("PROBE-FAIL: write CONNECT: %v", err)
		}
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			die("PROBE-FAIL: read reply: %v", err)
		}
		reply := strings.TrimSpace(string(buf[:n]))
		if !strings.HasPrefix(reply, "OK") {
			die("PROBE-FAIL: expected OK from the mediated endpoint, got %q", reply)
		}
		fmt.Printf("PROBE-OK: (%d,%d) round-tripped a CONNECT through the mux, reply=%q\n", cid, port, reply)
	default:
		die("probe expectation must be ok|reset, got %q", want)
	}
}

// nonic asserts the guest has NO network egress interface (the device-model half of no-direct-network):
// a TCP connect to a routable address must fail with no route / network unreachable, and there must be no
// non-loopback interface with an address.
func nonic() {
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		if len(addrs) > 0 {
			die("NONIC-FAIL: non-loopback interface %s has addresses %v — the guest has a NIC", ifc.Name, addrs)
		}
	}
	c, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err == nil {
		c.Close()
		die("NONIC-FAIL: a TCP connect to 1.1.1.1:443 SUCCEEDED — the guest has direct network egress")
	}
	fmt.Printf("NONIC-OK: no routable NIC; direct egress refused (%v)\n", err)
}

// stub is a test host endpoint that speaks the proxy CONNECT contract minimally: read one line, reply OK.
func stub(args []string) {
	if len(args) != 1 {
		die("usage: stub <uds>")
	}
	_ = os.Remove(args[0])
	ln, err := net.Listen("unix", args[0])
	if err != nil {
		die("stub listen: %v", err)
	}
	for {
		c := acceptNext(ln)
		if c == nil {
			return
		}
		go func() {
			defer c.Close()
			buf := make([]byte, 256)
			if _, err := c.Read(buf); err != nil {
				return
			}
			c.Write([]byte("OK\n"))
			io.Copy(io.Discard, c)
		}()
	}
}

// --- helpers ---

func mustPort(s string) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		die("bad number %q: %v", s, err)
	}
	return uint32(n)
}

// vsockDial opens an AF_VSOCK stream to (cid, port). Returns an *os.File over the connected fd — NOT a
// net.Conn, because net.FileConn rejects AF_VSOCK fds; *os.File Read/Write issue read(2)/write(2) on the
// socket, which is all the byte-transparent splice needs.
func vsockDial(cid, port uint32) (*fileConn, error) {
	fd, err := syscall.Socket(afVSOCK, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	sa := sockaddrVM{Family: afVSOCK, Port: port, CID: cid}
	if _, _, e := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); e != 0 {
		syscall.Close(fd)
		return nil, errors.New("vsock connect: " + e.Error())
	}
	// Make the fd non-blocking BEFORE os.NewFile so the runtime poller ADOPTS it — only then do
	// SetReadDeadline/SetWriteDeadline work on the *os.File (a blocking fd yields ErrNoDeadline, which is
	// what made splice's idle/total deadlines inert). The connect above is synchronous; a local host<->guest
	// vsock connect completes (or resets) fast, so a blocking connect is fine.
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &fileConn{f: os.NewFile(uintptr(fd), fmt.Sprintf("vsock:%d:%d", cid, port))}, nil
}

// fileConn adapts an *os.File (an AF_VSOCK fd) to the subset of net.Conn the splice uses, including a
// CloseWrite that shutdown(SHUT_WR)s the socket so half-close works across the vsock leg.
type fileConn struct{ f *os.File }

func (c *fileConn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *fileConn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *fileConn) Close() error                       { return c.f.Close() }
func (c *fileConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *fileConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }
func (c *fileConn) SetDeadline(t time.Time) error {
	if err := c.f.SetReadDeadline(t); err != nil {
		return err
	}
	return c.f.SetWriteDeadline(t)
}
func (c *fileConn) CloseWrite() error {
	sc, err := c.f.SyscallConn()
	if err != nil {
		return err
	}
	return sc.Control(func(fd uintptr) { syscall.Shutdown(int(fd), syscall.SHUT_WR) })
}

// halfCloser is the CloseWrite half-close both net.UnixConn and *fileConn provide.
type halfCloser interface{ CloseWrite() error }

// deadlineConn is the subset of net.Conn the splice uses; both net.UnixConn (the host legs) and *fileConn
// (the vsock leg, once its fd is non-blocking) satisfy it, so the idle/total deadlines actually take effect.
type deadlineConn interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// splice copies bytes both ways with a rolling IDLE deadline (re-armed per read) and an absolute TOTAL
// deadline, and half-closes (CloseWrite) the finishing direction so the proxy's OK/relay and the router's
// HTTP response are never truncated. Because each direction is bounded by idleTimeout/tunnelMax, a
// connection that connects then goes SILENT cannot block a copy forever — wg.Wait() returns, both conns
// close, and the per-leg cap slot is released. (Without these deadlines a silent guest connection pinned a
// slot forever and the conn-cap became a self-inflicted DoS.)
func splice(a, b deadlineConn) {
	total := time.Now().Add(tunnelMax)
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src deadlineConn) {
		defer wg.Done()
		copyIdle(dst, src, total)
		if hc, ok := dst.(halfCloser); ok {
			hc.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// copyIdle copies src->dst until EOF/error, re-arming a per-read idle deadline (capped by the total
// deadline) so a stalled direction is torn down rather than blocking forever.
func copyIdle(dst, src deadlineConn, total time.Time) {
	buf := make([]byte, 32*1024)
	for {
		rd := time.Now().Add(idleTimeout)
		if rd.After(total) {
			rd = total
		}
		_ = src.SetReadDeadline(rd)
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
