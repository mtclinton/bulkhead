// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// bulkhead provenance + OPT-IN BPF-LSM enforce (ADR-0004).
//
//   prov_socket_connect (lsm/socket_connect): provenance + OPT-IN per-agent egress
//     (E2). Logs every outbound connect; when armed, denies a connect whose
//     destination CLASS (loopback/linklocal/private/public/other, classified from
//     the sockaddr) is absent from the cgroup's egress manifest. No manifest =>
//     unrestricted (the nftables floor still applies) — composition, not duplication.
//   enforce_bpf (lsm/bpf, E0) / enforce_ptrace (lsm/ptrace_access_check, E1):
//     OPT-IN, FAIL-OPEN. Deny from non-TCB (agent) cgroups, but ONLY when the
//     per-hook enforce flag is set; every uncertain path returns the incoming ret
//     (allow). Deny requires ALL of:
//       ret==0  AND  cgroup not in the TCB allowlist  AND  enforce_flags[hook]==1.
//   enforce_setuid (lsm/task_fix_setuid, E3) / enforce_capset (lsm/capset, E3):
//     OPT-IN, FAIL-OPEN. Same gate, but deny only a privilege GAIN (regaining root /
//     raising caps) — drops are always allowed. The kernel itself permits these
//     gains, so the hooks ADD a denial for non-TCB cgroups.
//
// bpf is ordered LAST in lsm=landlock,lockdown,yama,bpf, and the dispatcher
// short-circuits on the first deny, so this can only ADD a denial atop the in-tree
// LSMs — never revert one. (6.6.127 has no verifier return-range guardrail, so we
// only ever deny from LSM_HOOK(int,0,...) hooks; lsm/bpf is one.)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define EPERM 1

#define AF_INET  2
#define AF_INET6 10

// hook ids — MUST match the userspace HOOK_* constants in main.go.
#define HOOK_BPF     0
#define HOOK_PTRACE  1
#define HOOK_CONNECT 3
#define HOOK_SETUID  4
#define HOOK_CAPSET  5

// E2 destination classes (a connect target's address class). The per-agent egress
// manifest is a bitmask of the classes a cgroup may reach — classified purely from
// the connect sockaddr, so there is NO IP-set to sync with the nftables allowlist.
// BPF gates *whether* an agent may attempt e.g. public egress at all; the host-wide
// dnsmasq->nftset floor still constrains *which* public IPs — composition, not
// duplication (ADR-0004). MUST match the DST_* constants in main.go.
#define DST_LOOPBACK  (1u << 0) // 127.0.0.0/8, ::1
#define DST_LINKLOCAL (1u << 1) // 169.254.0.0/16, fe80::/10
#define DST_PRIVATE   (1u << 2) // RFC1918 + 100.64/10 (CGNAT/tailnet) + fc00::/7 ULA
#define DST_PUBLIC    (1u << 3) // everything else routable
#define DST_OTHER     (1u << 4) // non-INET families (unix/netlink/...) — local IPC

struct event {
	__u64 cgroup_id;
	__u32 pid;
	__u8  comm[TASK_COMM_LEN]; // 16
	__u32 hook;      // HOOK_* id
	__u32 decision;  // 0 = allowed, 1 = denied (or would-deny in observe)
	__u32 mode;      // 0 = observe, 1 = enforce
};
// Force BTF emission of struct event so bpf2go -type event can generate it.
struct event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MiB, page-multiple power of two
} events SEC(".maps");

// Per-hook enforce toggle. key = HOOK_* id; value 0 = observe (would-deny logged,
// action allowed), 1 = enforce. Default (no entry / 0) = observe -> fail-open.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u32);
} enforce_flags SEC(".maps");

// TCB allowlist: cgroup ids permitted privileged actions (collector + init/root).
// presence (value 1) = allowed; absence = non-TCB (a deny candidate when armed).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);   // cgroup id
	__type(value, __u32); // 1 = TCB member
} tcb_cgroups SEC(".maps");

// E2 egress manifest: per-cgroup allowed destination-class mask. ABSENT => no
// manifest => unrestricted (fail-open; the nftables floor still applies). PRESENT
// => value is the bitmask of DST_* classes the cgroup may connect() to.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);   // cgroup id
	__type(value, __u32); // allowed DST_* mask
} egress_policy SEC(".maps");

// One-shot E1/E3 privilege grant (ADR-0011). A human-gated SINGLE-USE exception: when a
// hook is ARMED, an operator-approved grant lets an agent perform exactly ONE otherwise-
// denied ptrace/setuid/capset. Keyed PER (cgroup, hook) so a grant for one hook can NEVER
// satisfy another, and HOOK_BPF (E0) is never even looked up here (ungrantable). The
// explicit pads make the 16-byte key/value layout deterministic (no compiler tail padding
// the loader/verifier could disagree on) — same discipline as the fixed-offset probe_reads.
struct grant_key {
	__u64 cgid;
	__u32 hook; // HOOK_* id
	__u32 _pad;
};
struct grant_val {
	__u64 count;      // 1 = one unused grant; CAS 1->0 burns it. 64-bit: the BPF backend
	                  // (-mcpu=v1) only supports 64-bit atomic compare-and-swap.
	__u64 expire_ns;  // 0 = no TTL (v1 always writes 0; field reserved for a future TTL)
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct grant_key);
	__type(value, struct grant_val);
} grant_once SEC(".maps");

// try_consume_grant: returns 1 iff THIS caller won a live single-use grant for (cg,hook) and
// atomically burned it; 0 otherwise. Called ONLY on the would-deny path. CMPXCHG(count,1,0)
// resolves N racing agent threads to EXACTLY ONE winner: at most one sees prior==1, the count
// can never go negative (it only ever swaps to a fixed 0), and a double-consume is impossible
// (a second CAS sees 0 != 1). A miss / corrupted count / lapsed TTL => 0 => normal deny
// (fail-closed on the grant; the hook's underlying deny still stands).
static __always_inline int try_consume_grant(__u64 cg, __u32 hook)
{
	struct grant_key k = {};
	k.cgid = cg;
	k.hook = hook; // _pad stays 0 (zero-init): no uninitialized key bytes
	struct grant_val *v = bpf_map_lookup_elem(&grant_once, &k);
	if (!v)
		return 0;
	if (v->expire_ns != 0 && bpf_ktime_get_ns() > v->expire_ns)
		return 0; // TTL lapse (v1 writes 0 => never taken)
	if (__sync_val_compare_and_swap(&v->count, 1, 0) == 1) {
		// Best-effort tidy (no count==0 zombie). NB: if the broker re-grants the same
		// {cg,hook} in the tiny window after the CAS wins, this delete may drop that fresh
		// re-grant — which fails SAFE (the re-granted op is merely denied, never
		// over-permitted), so it is not relied upon for correctness. A leftover count==0 is
		// inert anyway (a later CAS sees 0!=1 and loses).
		bpf_map_delete_elem(&grant_once, &k);
		return 1; // the single granted instance -> allow
	}
	return 0; // lost the race / already spent
}

static __always_inline void log_decision(__u64 cg, __u32 hook, __u32 decision, __u32 mode)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return; // never block on provenance pressure
	e->cgroup_id = cg;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->hook = hook;
	e->decision = decision;
	e->mode = mode;
	bpf_ringbuf_submit(e, 0);
}

// Classify a routable IPv4 address (HOST byte order) into its DST_* class.
// Shared by the AF_INET path and the IPv4-mapped-IPv6 path below so both apply
// the SAME loopback/link-local/private ladder to an embedded v4 address.
static __always_inline __u32 classify_v4(__u32 a)
{
	__u8 o1 = a >> 24, o2 = (a >> 16) & 0xff;
	if (o1 == 127) return DST_LOOPBACK;                     // 127.0.0.0/8
	if (o1 == 169 && o2 == 254) return DST_LINKLOCAL;       // 169.254.0.0/16
	if (o1 == 10) return DST_PRIVATE;                       // 10.0.0.0/8
	if (o1 == 172 && (o2 & 0xf0) == 16) return DST_PRIVATE; // 172.16.0.0/12
	if (o1 == 192 && o2 == 168) return DST_PRIVATE;         // 192.168.0.0/16
	if (o1 == 100 && (o2 & 0xc0) == 64) return DST_PRIVATE; // 100.64.0.0/10
	return DST_PUBLIC;
}

// Classify a connect destination into a DST_* class from its sockaddr alone — no
// IP-set lookup, so nothing to keep in sync with the dnsmasq->nftset allowlist.
static __always_inline __u32 classify_dest(struct sockaddr *address)
{
	if (!address)
		return DST_OTHER;
	__u16 fam = 0;
	bpf_probe_read_kernel(&fam, sizeof(fam), &address->sa_family);

	if (fam == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)address;
		__be32 raw = 0;
		bpf_probe_read_kernel(&raw, sizeof(raw), &in->sin_addr.s_addr);
		return classify_v4(bpf_ntohl(raw));
	}

	if (fam == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)address;
		__u32 w[4] = {};
		bpf_probe_read_kernel(&w, sizeof(w), &in6->sin6_addr.in6_u.u6_addr32);
		if (w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == bpf_htonl(1))
			return DST_LOOPBACK;                            // ::1
		// IPv4-mapped IPv6 (::ffff:0:0/96): the kernel routes these as IPv4, so an
		// AF_INET6 connect to e.g. ::ffff:169.254.169.254 actually reaches the IPv4
		// link-local metadata endpoint. Classify by the EMBEDDED v4 address — same
		// ladder as AF_INET — so a v4-mapped loopback/link-local/private dest can't
		// slip through as DST_PUBLIC and bypass the per-class egress manifest.
		if (w[0] == 0 && w[1] == 0 && w[2] == bpf_htonl(0x0000ffff))
			return classify_v4(bpf_ntohl(w[3]));
		__u8 b0 = bpf_ntohl(w[0]) >> 24, b1 = (bpf_ntohl(w[0]) >> 16) & 0xff;
		if (b0 == 0xfe && (b1 & 0xc0) == 0x80) return DST_LINKLOCAL; // fe80::/10
		if ((b0 & 0xfe) == 0xfc) return DST_PRIVATE;            // fc00::/7 ULA
		return DST_PUBLIC;
	}

	return DST_OTHER; // unix/netlink/etc. — local IPC
}

// E2: per-agent egress authorization. Logs EVERY connect (full provenance) and,
// when armed, denies one whose destination class is absent from the cgroup's egress
// manifest. Fail-open: prior LSM deny honored; TCB always allowed; no manifest =>
// unrestricted; not armed => observe (would-deny logged, action allowed).
SEC("lsm/socket_connect")
int BPF_PROG(prov_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	if (ret != 0)
		return ret; // honor a prior LSM deny; never revert (one-way ratchet)

	__u64 cg = bpf_get_current_cgroup_id();
	__u32 cls = classify_dest(address);
	__u32 decision = 0, mode = 0; // default: allowed, observe
	int verdict = 0;

	__u32 *tcb = bpf_map_lookup_elem(&tcb_cgroups, &cg);
	if (!(tcb && *tcb == 1)) {
		__u32 *allowed = bpf_map_lookup_elem(&egress_policy, &cg);
		if (allowed && !(*allowed & cls)) {
			// manifest present and this destination class is not in it.
			__u32 hook = HOOK_CONNECT;
			__u32 *on = bpf_map_lookup_elem(&enforce_flags, &hook);
			mode = (on && *on == 1) ? 1 : 0; // miss/0 -> observe (fail-open)
			decision = 1;                    // (would-)deny
			if (mode)
				verdict = -EPERM;        // enforce: deny the egress
		}
	}

	log_decision(cg, HOOK_CONNECT, decision, mode);
	return verdict;
}

// Shared fail-open enforce verdict (identical skeleton for every enforce hook):
// deny ONLY when ret==0 AND the cgroup is not in the TCB allowlist AND the hook's
// enforce flag is explicitly 1. Every other path returns the incoming ret (allow).
// enforce_verdict_g is the grant-aware core. grantable=0 => the one-shot grant is NEVER
// consulted (E0/bpf passes 0, so no grant lookup is even compiled into that program — E0 is
// ungrantable BY CONSTRUCTION, not by a runtime branch). grantable=1 => on the ARMED
// would-deny path, an operator-approved single-use grant turns this one denial into an allow.
static __always_inline int enforce_verdict_g(__u32 hook, int ret, int grantable)
{
	if (ret != 0)
		return ret; // honor a prior LSM deny; never revert (one-way ratchet)

	__u64 cg = bpf_get_current_cgroup_id();

	__u32 *tcb = bpf_map_lookup_elem(&tcb_cgroups, &cg);
	if (tcb && *tcb == 1)
		return 0; // TCB (collector / init): always allow — BEFORE any grant consume

	__u32 *on = bpf_map_lookup_elem(&enforce_flags, &hook);
	__u32 enforce = (on && *on == 1) ? 1 : 0; // miss / 0 -> observe (fail-open)

	if (!enforce) {
		log_decision(cg, hook, 0, 0); // observe: logged the would-deny, ALLOW, NO consume
		return 0;
	}
	// ARMED would-deny path reached ONLY here. E0 (grantable==0) short-circuits => no lookup.
	if (grantable && try_consume_grant(cg, hook)) {
		log_decision(cg, hook, 0, 1); // decision=allowed, mode=enforce: a single granted op
		return 0;
	}
	log_decision(cg, hook, 1, 1);
	return -EPERM; // enforce: deny the agent-originated action
}

// Backward-compatible non-consuming wrapper (E0 path is textually unchanged).
static __always_inline int enforce_verdict(__u32 hook, int ret)
{
	return enforce_verdict_g(hook, ret, 0);
}

// E0: deny bpf() from agent cgroups (protect the BPF substrate the TCB rests on). NOT
// one-shot-grantable: the substrate must never be relaxable, even by an operator.
SEC("lsm/bpf")
int BPF_PROG(enforce_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
	return enforce_verdict(HOOK_BPF, ret);
}

// E1: deny ptrace_access_check from agent cgroups (agents may not ptrace/inspect
// other processes). Yama's ptrace_scope is host-wide; this is per-agent. GRANTABLE.
SEC("lsm/ptrace_access_check")
int BPF_PROG(enforce_ptrace, struct task_struct *child, unsigned int mode, int ret)
{
	return enforce_verdict_g(HOOK_PTRACE, ret, 1);
}

// Shared gate for E3 privilege-GAIN hooks: deny (when armed) a non-TCB cgroup that
// is raising privilege; ALWAYS allow drops/no-ops. `gain` (computed by the caller)
// is 1 iff this transition raises privilege. Same fail-open discipline as above.
static __always_inline int enforce_gain(__u32 hook, int ret, int gain)
{
	if (ret != 0)
		return ret; // honor a prior LSM deny; never revert
	if (!gain)
		return 0;   // privilege drop or no change: always allow

	__u64 cg = bpf_get_current_cgroup_id();
	__u32 *tcb = bpf_map_lookup_elem(&tcb_cgroups, &cg);
	if (tcb && *tcb == 1)
		return 0;   // TCB (collector / init): always allow

	__u32 *on = bpf_map_lookup_elem(&enforce_flags, &hook);
	__u32 enforce = (on && *on == 1) ? 1 : 0; // miss/0 -> observe (fail-open)
	if (!enforce) {
		log_decision(cg, hook, 1, 0); // observe would-deny: logged, ALLOW, NO consume
		return 0;
	}
	// ARMED + gain + non-TCB: a one-shot grant (ADR-0011) spends here, before the deny.
	if (try_consume_grant(cg, hook)) {
		log_decision(cg, hook, 0, 1); // decision=allowed, mode=enforce: a single granted gain
		return 0;
	}
	log_decision(cg, hook, 1, 1);
	return -EPERM; // enforce: deny the escalation
}

// E3: deny an agent cgroup GAINING effective root via the setuid family; allow
// drops. Gain = acquiring euid 0 the task did not have (e.g. regaining root from a
// retained suid=0) — a transition the kernel itself permits, so this adds a denial.
SEC("lsm/task_fix_setuid")
int BPF_PROG(enforce_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
	__u32 ne = 1, oe = 1; // default !=0 -> no gain -> allow on a failed read (fail-open)
	bpf_probe_read_kernel(&ne, sizeof(ne), &new->euid.val);
	bpf_probe_read_kernel(&oe, sizeof(oe), &old->euid.val);
	int gain = (ne == 0 && oe != 0);
	return enforce_gain(HOOK_SETUID, ret, gain);
}

// E3: deny an agent cgroup GAINING capabilities (effective or permitted) via capset;
// allow drops. Raising effective within an already-held permitted set is kernel-
// permitted, so this adds a denial. kernel_cap_t is a single u64 on 6.6.
SEC("lsm/capset")
int BPF_PROG(enforce_capset, struct cred *new, const struct cred *old,
	     const kernel_cap_t *effective, const kernel_cap_t *inheritable,
	     const kernel_cap_t *permitted, int ret)
{
	__u64 ne = 0, oe = 0, np = 0, op = 0;
	bpf_probe_read_kernel(&ne, sizeof(ne), effective);            // requested effective
	bpf_probe_read_kernel(&oe, sizeof(oe), &old->cap_effective.val);
	bpf_probe_read_kernel(&np, sizeof(np), permitted);           // requested permitted
	bpf_probe_read_kernel(&op, sizeof(op), &old->cap_permitted.val);
	int gain = ((ne & ~oe) != 0) || ((np & ~op) != 0);
	return enforce_gain(HOOK_CAPSET, ret, gain);
}
