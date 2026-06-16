// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Host-side unit tests for the approval-gate concurrency (ADR-0007) — the
// register/resolve registry must deliver a verdict EXACTLY ONCE and resolve the
// operator-decision-vs-timeout race deterministically, without a VM.
package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestNarrowComputesMask guards ADR-0010's clamp arithmetic: narrowMask = cur &^ req can only
// CLEAR bits (monotone-decreasing, fail-safe direction), and a requested class the agent
// lacks is a no-op on that class.
func TestNarrowComputesMask(t *testing.T) {
	lp, _ := parseClasses("loopback")
	pub, _ := parseClasses("public")
	oth, _ := parseClasses("other")
	all, _ := parseClasses("loopback,linklocal,private,public,other")
	cases := []struct {
		name           string
		cur, req, want uint32
	}{
		{"clears a held bit", lp | pub, pub, lp},
		{"unheld class is a no-op on it", lp | oth, pub, lp | oth},
		{"clamp all -> none", all, all, 0},
		{"multi clear", lp | pub | oth, pub | oth, lp},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := narrowMask(c.cur, c.req)
			if got != c.want {
				t.Fatalf("narrowMask(%#x,%#x)=%#x, want %#x", c.cur, c.req, got, c.want)
			}
			if got&^c.cur != 0 {
				t.Fatalf("narrow SET a bit: %#x is not a subset of cur %#x", got, c.cur)
			}
			if got&c.req != 0 {
				t.Fatalf("narrow left a requested bit set: req %#x still in %#x", c.req, got)
			}
		})
	}
}

// TestResolveAgentTargetRejectsNonAgent guards ADR-0010's target gate: narrow may only ever
// resolve a cgroup under /bulkhead-agent.slice/bulkhead-agent@ — never the TCB, PID-1, the
// operator's own session, an id:N, a traversal, or a malformed instance.
func TestResolveAgentTargetRejectsNonAgent(t *testing.T) {
	if _, _, err := resolveAgentTarget("id:42"); !errors.Is(err, errNarrowID) {
		t.Fatalf("id:42 -> %v, want errNarrowID", err)
	}
	for _, p := range []string{
		"/system.slice/bulkhead-collector.service",
		"/sys/fs/cgroup/system.slice/bulkhead-broker.service",
		"/bulkhead-agent.slice/../system.slice/x.service", // traversal escaping the slice
	} {
		if _, _, err := resolveAgentTarget(p); !errors.Is(err, errNarrowNotAgent) {
			t.Fatalf("%q -> %v, want errNarrowNotAgent", p, err)
		}
	}
	for _, b := range []string{"../etc", "a/b", "WithCaps", "has.dot"} {
		if _, _, err := resolveAgentTarget(b); !errors.Is(err, errNarrowBadInst) {
			t.Fatalf("bad instance %q -> %v, want errNarrowBadInst", b, err)
		}
	}
	// A well-formed but nonexistent agent passes the slice predicate, then fails at the live
	// stat — proving the gate did NOT reject it (it's a real attempt that simply isn't running).
	if _, _, err := resolveAgentTarget("nonexistent-agent-xyz"); !errors.Is(err, errNarrowGone) {
		t.Fatalf("nonexistent agent -> %v, want errNarrowGone", err)
	}
}

// TestReverifyCgroupRebindsIdentity guards the F1/F3 re-binding: at execute() time the
// requester's attested cgroup id must still match the LIVE inode at its path, or the action
// fails closed (recycle onto a new agent, or a vanished cgroup). Exercised against the
// cgroup root, which always exists on a cgroup-v2 host.
func TestReverifyCgroupRebindsIdentity(t *testing.T) {
	const root = "" // filepath.Join("/sys/fs/cgroup", "") -> /sys/fs/cgroup
	live, err := cgroupIDFromInode(filepath.Join("/sys/fs/cgroup", root))
	if err != nil {
		t.Skipf("no cgroupfs on build host: %v", err)
	}
	if err := reverifyCgroup(root, live); err != nil {
		t.Fatalf("reverify of the live id must pass: %v", err)
	}
	if err := reverifyCgroup(root, live+1); err == nil {
		t.Fatal("reverify of a recycled (mismatched) id must fail closed")
	}
	if err := reverifyCgroup("/bulkhead-nonexistent.slice/nope.service", live); err == nil {
		t.Fatal("reverify of a vanished path must fail closed")
	}
}

// TestValidTask guards ADR-0015's task sanitizer (defense-in-depth behind the non-unit
// channel): empty + clean printable-ASCII pass; NUL / newline / CR / tab / DEL / any non-ASCII
// byte / over-4096 all fail closed so a hostile task spawns no child.
func TestValidTask(t *testing.T) {
	if err := validTask(""); err != nil {
		t.Fatalf("empty task must be allowed (broker default): %v", err)
	}
	if err := validTask("Fetch https://api.anthropic.com/ and report the HTTP status."); err != nil {
		t.Fatalf("clean ASCII task must pass: %v", err)
	}
	for name, s := range map[string]string{
		"NUL":        "a\x00b",
		"newline":    "do x\nExecStartPre=+/bin/touch /pwned",
		"CR":         "a\rb",
		"tab":        "a\tb",
		"DEL":        "a\x7fb",
		"high-byte":  "café", // é => 0xc3 0xa9
		"unicode-LS": "a b",  // line separator => e2 80 a8
	} {
		if err := validTask(s); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	if err := validTask(strings.Repeat("a", 4097)); err == nil {
		t.Fatal("a 4097-byte task must be rejected")
	}
	if err := validTask(strings.Repeat("a", 4096)); err != nil {
		t.Fatalf("a 4096-byte task must pass: %v", err)
	}
}

// TestDelegGen guards the depth derivation: it must come ONLY from the kernel-attested parent
// instance name. A top-level parent (worker/agentA) is gen 0; a minted child d<N>-… is gen N;
// the legacy d-<hex> form reads as gen 0; a path with no agent instance fails closed.
func TestDelegGen(t *testing.T) {
	for _, c := range []struct {
		path string
		want int
		err  bool
	}{
		{"/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@worker.service", 0, false},
		{"/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@agentA.service", 0, false},
		{"/x/bulkhead-agent@d1-deadbeef-probe.service", 1, false},
		{"/x/bulkhead-agent@d2-cafef00d-y.service", 2, false},
		{"/x/bulkhead-agent@d10-aaaaaaaa-z.service", 10, false},
		{"/x/bulkhead-agent@d-oldstyle-z.service", 0, false}, // legacy d-<hex>: not d<digit>- => gen 0
		{"/x/bulkhead-agent@d2foo.service", 0, false},        // d<digit> but no '-' => a name, gen 0
		{"/system.slice/bulkhead-collector.service", 0, true},
	} {
		got, err := delegGen(c.path)
		if c.err {
			if err == nil {
				t.Fatalf("delegGen(%q) want error", c.path)
			}
			continue
		}
		if err != nil {
			t.Fatalf("delegGen(%q): %v", c.path, err)
		}
		if got != c.want {
			t.Fatalf("delegGen(%q)=%d want %d", c.path, got, c.want)
		}
	}
}

// TestParseDelegateTail: <3 fields => not ok; exactly 3 => task ""; >3 => f[3:] joined.
func TestParseDelegateTail(t *testing.T) {
	if _, _, _, ok := parseDelegateTail([]string{"DELEGATE", "foo"}); ok {
		t.Fatal("a <3-field line must not parse")
	}
	if s, c, task, ok := parseDelegateTail([]string{"DELEGATE", "foo", "public"}); !ok || s != "foo" || c != "public" || task != "" {
		t.Fatalf("no-task parse = %q %q %q ok=%v", s, c, task, ok)
	}
	if s, c, task, ok := parseDelegateTail([]string{"DELEGATE", "foo", "public", "a", "b", "c"}); !ok || s != "foo" || c != "public" || task != "a b c" {
		t.Fatalf("task parse = %q %q %q ok=%v", s, c, task, ok)
	}
}

// TestDelegatedDropInNoTaskBytes is the core injection proof: the drop-in is built ONLY from
// broker-controlled tokens, and the parent task NEVER appears in it (it rides a credential).
func TestDelegatedDropInNoTaskBytes(t *testing.T) {
	// A hostile task that PASSES validTask (no control chars) — proving even a sanitizer-passing
	// payload cannot reach unit syntax, because delegatedDropIn does not consume the task at all.
	hostile := "do X ExecStartPre=+/bin/touch /pwned [Service] User=root"
	out := delegatedDropIn("loopback,other", "d1-deadbeef-kid", "http://127.0.0.1:8088", true)
	for _, want := range []string{
		"ExecStart=\nExecStart=/usr/bin/bulkhead-agent %i\n",
		"Environment=BULKHEAD_AGENT_EGRESS=loopback,other\n",
		"Environment=BULKHEAD_AGENT_ALLOW_DELEGATE=1\n", // delegation flows down a lineage (depth-capped)
		"Environment=BULKHEAD_AGENT_NO_EXPAND=1\n",       // a delegated child cannot self-widen (lifetime narrow-never-widen)
		"LoadCredential=agent-task:/run/bulkhead/tasks/d1-deadbeef-kid.task\n",
		"Environment=BULKHEAD_AGENT_TASK_CRED=agent-task\n",
		"Environment=\"BULKHEAD_ROUTER_URL=http://127.0.0.1:8088\"\n", // double-quoted hardening (security audit)
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("drop-in missing fixed line %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, hostile) || strings.Contains(out, "/pwned") || strings.Contains(out, "ExecStartPre") {
		t.Fatalf("task bytes leaked into the drop-in:\n%s", out)
	}
	if strings.Count(out, "[Service]") != 1 {
		t.Fatalf("drop-in must have exactly one [Service] section:\n%s", out)
	}
	// No-task path: a benign default task, NO LoadCredential, and an empty routerURL omits the line.
	out0 := delegatedDropIn("loopback", "d1-x-y", "", false)
	if strings.Contains(out0, "LoadCredential") {
		t.Fatalf("no-task drop-in must not LoadCredential:\n%s", out0)
	}
	if !strings.Contains(out0, "BULKHEAD_AGENT_TASK=") {
		t.Fatalf("no-task drop-in needs a default task:\n%s", out0)
	}
	if strings.Contains(out0, "BULKHEAD_ROUTER_URL") {
		t.Fatalf("an empty routerURL must omit the line:\n%s", out0)
	}
}

// TestDelegateDepthCap: a parent at the max generation gets ERR too-deep and NO pending is
// registered (no side effect). The check sits before the BPF map read, so this runs kernel-free
// over an in-memory pipe.
func TestDelegateDepthCap(t *testing.T) {
	resetPend()
	parentPath := "/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@d" +
		strconv.Itoa(maxDelegateDepth) + "-deadbeef-x.service"
	c1, c2 := net.Pipe()
	got := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(c2).ReadString('\n')
		got <- strings.TrimSpace(line)
		_, _ = io.Copy(io.Discard, c2)
	}()
	handleDelegateTail(c1, 1234, parentPath, []string{"DELEGATE", "kid", "loopback"})
	_ = c1.Close()
	if reply := <-got; reply != "ERR too-deep" {
		t.Fatalf("at max depth, reply=%q want ERR too-deep", reply)
	}
	pendMu.Lock()
	n := len(pend)
	pendMu.Unlock()
	if n != 0 {
		t.Fatalf("a too-deep delegate registered %d pending, want 0 (no side effect)", n)
	}
}

// TestExpandRefusedForDelegatedChild (security review R2): a broker-minted delegated child (gen>0,
// attested from its d<N>- instance name — the same un-spoofable signal the depth cap uses) is refused
// EXPAND in the TCB, regardless of the in-jail NO_EXPAND env it could bypass. A top-level agent (gen 0)
// is NOT blanket-refused. (delegGen's parsing of the attested path is itself covered by TestDelegGen,
// and that the kernel attestation yields the right d<N>- path is live-proven by ARM DEPTHCAP.)
func TestExpandRefusedForDelegatedChild(t *testing.T) {
	resetPend()
	ask := func(path string) string {
		c1, c2 := net.Pipe()
		got := make(chan string, 1)
		go func() {
			line, _ := bufio.NewReader(c2).ReadString('\n')
			got <- strings.TrimSpace(line)
			_, _ = io.Copy(io.Discard, c2)
		}()
		handleExpandTail(c1, 1234, path, []string{"EXPAND", "public"})
		_ = c1.Close()
		return <-got
	}
	childPath := "/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@d1-deadbeef-kid.service"
	if r := ask(childPath); r != "ERR no-expand-for-delegated" {
		t.Fatalf("a delegated child's EXPAND must be refused in the broker, reply=%q want ERR no-expand-for-delegated", r)
	}
	pendMu.Lock()
	n := len(pend)
	pendMu.Unlock()
	if n != 0 {
		t.Fatalf("a refused delegated EXPAND registered %d pending, want 0 (no side effect)", n)
	}
	// A top-level agent (gen 0) passes the gen-check and proceeds (here hitting the no-manifest path,
	// since the unit test has no pinned BPF map) — proving the cap is scoped to delegated children only.
	if r := ask("/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@worker.service"); r == "ERR no-expand-for-delegated" {
		t.Fatalf("a top-level agent must NOT be blanket-refused EXPAND, reply=%q", r)
	}
}

// resetPend clears the global registry between tests.
func resetPend() {
	pendMu.Lock()
	pend = map[uint64]*pending{}
	pendPerPar = map[uint64]int{}
	pendNext = 0
	pendMu.Unlock()
}

func TestRegisterResolveExactlyOnce(t *testing.T) {
	resetPend()
	p := &pending{parentCgID: 100}
	if !register(p) {
		t.Fatal("register failed")
	}
	if got := resolve(p.id, true, "approve", "op"); !got {
		t.Fatal("first resolve should win")
	}
	if v := <-p.decision; v != true {
		t.Fatalf("decision = %v, want true", v)
	}
	if p.verdict != "approve" || p.operator != "op" {
		t.Fatalf("verdict/operator = %q/%q", p.verdict, p.operator)
	}
	// A second resolve (a late operator decision or the timeout) must be a no-op.
	if got := resolve(p.id, false, "timeout", "-"); got {
		t.Fatal("second resolve must be a no-op")
	}
	// Registry must be empty + per-parent counter decremented.
	pendMu.Lock()
	if len(pend) != 0 || pendPerPar[100] != 0 {
		t.Fatalf("registry not cleaned: pend=%d perPar=%d", len(pend), pendPerPar[100])
	}
	pendMu.Unlock()
}

// TestResolveRaceSingleDelivery: many goroutines racing allow-vs-timeout on one entry;
// exactly one wins, the decision channel receives exactly one value, no double-launch.
func TestResolveRaceSingleDelivery(t *testing.T) {
	for iter := 0; iter < 200; iter++ {
		resetPend()
		p := &pending{parentCgID: 7}
		register(p)
		var wins int32
		var wg sync.WaitGroup
		results := make(chan bool, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			allow := i%2 == 0
			go func() {
				defer wg.Done()
				if resolve(p.id, allow, "v", "op") {
					results <- allow
				}
			}()
		}
		// exactly one resolve wins -> exactly one channel value
		got := <-p.decision
		wg.Wait()
		close(results)
		for range results {
			wins++
		}
		if wins != 1 {
			t.Fatalf("iter %d: %d resolvers reported winning, want 1", iter, wins)
		}
		_ = got
	}
}

func TestFloodCaps(t *testing.T) {
	resetPend()
	// per-parent cap
	for i := 0; i < maxPendingPar; i++ {
		if !register(&pending{parentCgID: 42}) {
			t.Fatalf("register %d under per-parent cap should succeed", i)
		}
	}
	if register(&pending{parentCgID: 42}) {
		t.Fatal("register past per-parent cap must be rejected")
	}
	// a different parent is unaffected (until the global cap)
	if !register(&pending{parentCgID: 43}) {
		t.Fatal("a different parent under caps should succeed")
	}
}

// TestExpandComputesMask: the widen arithmetic — add requested classes within the
// ceiling, never beyond it, never remove a held class.
func TestExpandComputesMask(t *testing.T) {
	all := dstLoopback | dstLinklocal | dstPrivate | dstPublic | dstOther
	for _, c := range []struct {
		cur, req, ceiling, want uint32
	}{
		{dstLoopback | dstOther, dstPublic, all, dstLoopback | dstOther | dstPublic}, // add public
		{dstLoopback | dstOther, dstLoopback, all, dstLoopback | dstOther},           // already held -> no change
		{dstLoopback, dstPublic, dstLoopback | dstOther, dstLoopback},                // public above ceiling -> clamped
		{dstLoopback, dstPublic | dstPrivate, dstPublic, dstLoopback | dstPublic},    // only the in-ceiling bit added
		{0, dstPublic, all, dstPublic},                                               // from empty (note: handler refuses no-manifest separately)
	} {
		if got := expandMask(c.cur, c.req, c.ceiling); got != c.want {
			t.Errorf("expandMask(0x%x,0x%x,0x%x)=0x%x want 0x%x", c.cur, c.req, c.ceiling, got, c.want)
		}
		// widening never removes a held class:
		if got := expandMask(c.cur, c.req, c.ceiling); got&c.cur != c.cur {
			t.Errorf("expandMask dropped a held class: cur=0x%x got=0x%x", c.cur, got)
		}
	}
}

// TestGateActionAgnostic: the register/resolve gate delivers a verdict exactly once for a
// NON-delegate action kind too (the gate is the reusable substrate).
func TestGateActionAgnostic(t *testing.T) {
	resetPend()
	p := &pending{kind: actExpandEgress, parentCgID: 9}
	if !register(p) {
		t.Fatal("register expand pending failed")
	}
	if !resolve(p.id, true, "approve", "op") {
		t.Fatal("first resolve should win")
	}
	if v := <-p.decision; v != true || p.verdict != "approve" {
		t.Fatalf("decision=%v verdict=%q", v, p.verdict)
	}
	if resolve(p.id, false, "deny", "op2") {
		t.Fatal("second resolve must be a no-op (exactly-once)")
	}
}
