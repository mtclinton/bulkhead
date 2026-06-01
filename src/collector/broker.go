// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Inter-agent egress delegation broker (ADR-0006). A parent agent (jailed, non-root,
// no caps, cannot bpf()) asks this TCB broker to spawn a child whose egress manifest is
// child = parent ∩ requested — NARROW-NEVER-WIDEN. The broker is the only thing that
// reads the live egress_policy map and launches a jail; the parent is untrusted and
// supplies ONLY a cosmetic child-suffix and a requested class set. Every identity input
// (which cgroup is asking, hence its ceiling) is attested by the kernel via SO_PEERPIDFD,
// never by anything the parent sends.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const brokerSockPath = "/run/bulkhead/broker.sock"

// ---- broker (TCB listener) -------------------------------------------------

func cmdBroker() {
	// Self-register our own cgroup in the TCB allowlist so our bpf() map ops survive
	// E0 (lsm/bpf deny) and our own connects are E2-exempt. Requires E0 to be OFF at
	// this first call (the MVP default); see ADR-0006.
	if err := brokerSelfRegisterTCB(); err != nil {
		log.Fatalf("broker: self-register TCB (is the collector running?): %v", err)
	}
	ln, err := brokerListener()
	if err != nil {
		log.Fatalf("broker: listen: %v", err)
	}
	log.Printf("broker: listening (delegation: child = parent ∩ requested)")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("broker: accept: %v", err)
			continue
		}
		handleDelegate(conn) // serialized: one request per connection
	}
}

// brokerListener prefers systemd socket activation (LISTEN_FDS fd 3); else binds the path.
func brokerListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) && os.Getenv("LISTEN_FDS") != "" {
		f := os.NewFile(3, "bulkhead-broker.sock") // SD_LISTEN_FDS_START
		defer f.Close()
		return net.FileListener(f)
	}
	_ = os.Remove(brokerSockPath)
	if err := os.MkdirAll(filepath.Dir(brokerSockPath), 0o755); err != nil {
		return nil, err
	}
	return net.Listen("unix", brokerSockPath)
}

func brokerSelfRegisterTCB() error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "tcb_cgroups"), nil)
	if err != nil {
		return err
	}
	defer m.Close()
	cg, err := resolveCgroupID("self")
	if err != nil {
		return err
	}
	return m.Update(cg, uint32(1), ebpf.UpdateAny)
}

func handleDelegate(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second)) // a slow/hostile peer can't wedge the loop
	reply := func(s string) { fmt.Fprintln(conn, s) }

	// 1. Kernel-attested parent identity (NEVER from the request body).
	parentCgID, parentPath, err := peerParentCgID(conn)
	if err != nil {
		log.Printf("broker: peer-auth: %v", err)
		reply("ERR peer-auth")
		return
	}
	// Only a real jailed agent may delegate (and a TCB process must not use this path).
	if !strings.Contains(parentPath, "/bulkhead-agent.slice/bulkhead-agent@") {
		log.Printf("broker: reject non-agent parent cgroup %q", parentPath)
		reply("ERR not-an-agent")
		return
	}

	// 2. Request line: DELEGATE <child-suffix> <requested-classes>
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		reply("ERR read")
		return
	}
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) != 3 || f[0] != "DELEGATE" {
		reply("ERR protocol")
		return
	}
	suffix, reqStr := f[1], f[2]
	if !validSuffix(suffix) {
		reply("ERR bad-suffix")
		return
	}
	reqMask, err := parseClasses(reqStr)
	if err != nil {
		reply("ERR bad-classes")
		return
	}

	// 3. Parent's CURRENT ceiling from the live pinned map. Miss => cannot delegate
	//    (you cannot safely subset "unrestricted"). Fail-closed.
	parentMask, err := lookupEgressMask(parentCgID)
	if err != nil {
		reply("ERR no-parent-manifest")
		return
	}

	// 4. NARROW-NEVER-WIDEN: bitwise AND can only clear bits.
	childMask := parentMask & reqMask

	// 5. Human approval-gate seam (next slice). Stub: always allow. Fail-closed on deny.
	if !approveDelegation(parentCgID, suffix, childMask) {
		reply("ERR denied")
		return
	}

	// 6. Launch the child as a normal jail instance; its +ExecStartPre writes the
	//    (narrowed) manifest in the child's own cgroup before the payload forks.
	instance := "d-" + randHex8() + "-" + suffix
	if err := launchChild(instance, classNames(childMask)); err != nil {
		log.Printf("broker: launch %s: %v", instance, err)
		reply("ERR launch")
		return
	}
	log.Printf("broker: delegated parent-cg=%d (mask 0x%02x) requested 0x%02x -> child %s mask 0x%02x (%s)",
		parentCgID, parentMask, reqMask, instance, childMask, classNames(childMask))
	reply(fmt.Sprintf("OK %s %s", instance, classNames(childMask)))
}

// peerParentCgID attests the connecting agent's cgroup id from the kernel. SO_PEERPIDFD
// captures, at connect() time, a pidfd bound to the connecting task's struct pid — which
// pins the pid NUMBER against recycle while we hold it, closing the connect→read TOCTOU.
// We read the authoritative pid from the pidfd's fdinfo, then that pid's cgroup.
func peerParentCgID(conn net.Conn) (uint64, string, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, "", fmt.Errorf("not a unix conn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, "", err
	}
	var pidfd int
	var sockErr error
	if cerr := raw.Control(func(fd uintptr) {
		pidfd, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); cerr != nil {
		return 0, "", cerr
	}
	if sockErr != nil {
		return 0, "", fmt.Errorf("SO_PEERPIDFD: %w", sockErr)
	}
	defer unix.Close(pidfd)

	pid, err := pidFromPidfd(pidfd)
	if err != nil {
		return 0, "", err
	}
	// The pidfd pins the connecting task's struct pid, which RESERVES the pid number
	// against recycle for as long as we hold the fd. So /proc/<pid>/cgroup is provably
	// the original parent's: it is either that task (alive or zombie) or absent (if
	// reaped) — never a different process. A reaped parent => ReadFile fails => we
	// fail closed below. (No signal-based liveness recheck: it would need CAP_KILL to
	// signal the parent's DynamicUser uid, and the pin already makes it redundant.)
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, "", fmt.Errorf("read peer cgroup: %w", err)
	}
	path := cgroupPathFromBytes(data)
	if path == "" {
		return 0, "", fmt.Errorf("no v2 cgroup line for peer")
	}
	cg, err := cgroupIDFromInode(filepath.Join("/sys/fs/cgroup", path))
	if err != nil {
		return 0, "", err
	}
	return cg, path, nil
}

func pidFromPidfd(pidfd int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", pidfd))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Pid:") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}
	return 0, fmt.Errorf("no Pid in pidfd fdinfo")
}

func cgroupPathFromBytes(data []byte) string {
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") { // v2 unified hierarchy
			return strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}

func lookupEgressMask(cgID uint64) (uint32, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	var mask uint32
	if err := m.Lookup(cgID, &mask); err != nil {
		return 0, err // miss => parent has no manifest => may not delegate
	}
	return mask, nil
}

func validSuffix(s string) bool {
	if len(s) < 1 || len(s) > 24 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func randHex8() string {
	var b [4]byte
	_, _ = rand.Read(b[:]) // crypto/rand
	return hex.EncodeToString(b[:])
}

// launchChild writes a transient /run drop-in carrying the narrowed manifest, then
// starts the jail instance. systemctl start blocks until the unit's +ExecStartPre (which
// writes egress_policy[child]) and ExecStart have run, so the broker only replies OK once
// the child's manifest is in the map — the child payload cannot connect() before that.
func launchChild(instance, classes string) error {
	unit := "bulkhead-agent@" + instance + ".service"
	dropDir := filepath.Join("/run/systemd/system", unit+".d")
	if err := os.MkdirAll(dropDir, 0o755); err != nil {
		return err
	}
	conf := "[Service]\nEnvironment=BULKHEAD_AGENT_EGRESS=" + classes + "\n"
	if err := os.WriteFile(filepath.Join(dropDir, "20-delegated-egress.conf"), []byte(conf), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %v: %s", err, out)
	}
	if out, err := exec.Command("systemctl", "start", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("start %s: %v: %s", unit, err, out)
	}
	return nil
}

// approveDelegation is the human approval-gate seam (the next slice). For this MVP it is
// a stub that always allows; the next slice makes it block on operator ack and return
// false on denial/timeout — fail-closed, same reply path, NO child cgroup created on deny.
func approveDelegation(parentCgID uint64, suffix string, childMask uint32) bool {
	return true
}

// ---- delegate (client run by the parent agent INSIDE its jail) -------------

func cmdDelegate(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector delegate <child-suffix> <requested-classes>")
		os.Exit(2)
	}
	conn, err := net.DialTimeout("unix", brokerSockPath, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "delegate: dial broker: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second)) // the broker blocks on child start
	if _, err := fmt.Fprintf(conn, "DELEGATE %s %s\n", args[0], args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "delegate: send: %v\n", err)
		os.Exit(1)
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "delegate: read reply: %v\n", err)
		os.Exit(1)
	}
	resp = strings.TrimSpace(resp)
	fmt.Println(resp)
	if !strings.HasPrefix(resp, "OK ") {
		os.Exit(1)
	}
}
