// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// bulkhead provenance + OPT-IN BPF-LSM enforce (ADR-0004).
//
//   prov_socket_connect (lsm/socket_connect): OBSERVE-ONLY. Records every outbound
//     connect and ALWAYS returns the incoming verdict (ret) unchanged.
//   enforce_bpf (lsm/bpf): OPT-IN, FAIL-OPEN. Denies bpf() from non-TCB (agent)
//     cgroups, but ONLY when the per-hook enforce flag is explicitly set; every
//     uncertain path returns the incoming ret (allow). Deny requires ALL of:
//       ret==0  AND  cgroup not in the TCB allowlist  AND  enforce_flags[bpf]==1.
//
// bpf is ordered LAST in lsm=landlock,lockdown,yama,bpf, and the dispatcher
// short-circuits on the first deny, so this can only ADD a denial atop the in-tree
// LSMs — never revert one. (6.6.127 has no verifier return-range guardrail, so we
// only ever deny from LSM_HOOK(int,0,...) hooks; lsm/bpf is one.)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define EPERM 1

// hook ids — MUST match the userspace HOOK_* constants in main.go.
#define HOOK_BPF     0
#define HOOK_PTRACE  1
#define HOOK_CONNECT 3

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

SEC("lsm/socket_connect")
int BPF_PROG(prov_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	log_decision(bpf_get_current_cgroup_id(), HOOK_CONNECT, 0, 0);
	return ret; // OBSERVE-ONLY: honor the incoming verdict
}

// Shared fail-open enforce verdict (identical skeleton for every enforce hook):
// deny ONLY when ret==0 AND the cgroup is not in the TCB allowlist AND the hook's
// enforce flag is explicitly 1. Every other path returns the incoming ret (allow).
static __always_inline int enforce_verdict(__u32 hook, int ret)
{
	if (ret != 0)
		return ret; // honor a prior LSM deny; never revert (one-way ratchet)

	__u64 cg = bpf_get_current_cgroup_id();

	__u32 *tcb = bpf_map_lookup_elem(&tcb_cgroups, &cg);
	if (tcb && *tcb == 1)
		return 0; // TCB (collector / init): always allow

	__u32 *on = bpf_map_lookup_elem(&enforce_flags, &hook);
	__u32 enforce = (on && *on == 1) ? 1 : 0; // miss / 0 -> observe (fail-open)

	log_decision(cg, hook, enforce ? 1 : 0, enforce);

	if (!enforce)
		return 0;      // observe: logged the would-deny, but ALLOW
	return -EPERM;         // enforce: deny the agent-originated action
}

// E0: deny bpf() from agent cgroups (protect the BPF substrate the TCB rests on).
SEC("lsm/bpf")
int BPF_PROG(enforce_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
	return enforce_verdict(HOOK_BPF, ret);
}

// E1: deny ptrace_access_check from agent cgroups (agents may not ptrace/inspect
// other processes). Yama's ptrace_scope is host-wide; this is per-agent.
SEC("lsm/ptrace_access_check")
int BPF_PROG(enforce_ptrace, struct task_struct *child, unsigned int mode, int ret)
{
	return enforce_verdict(HOOK_PTRACE, ret);
}
