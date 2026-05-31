// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// bulkhead provenance: OBSERVE-ONLY BPF-LSM instrumentation.
//
// This program attaches to the socket_connect LSM hook and records the acting
// process for every outbound connect, then ALWAYS returns the incoming verdict
// (ret) unchanged. It never enforces — enforcement is the seccomp/Landlock/
// nftables floor. Because the BPF LSM runs after the in-tree LSMs and returning
// the prior ret cannot revert an earlier denial, this cannot weaken the floor.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct event {
	__u64 cgroup_id;
	__u32 pid;
	__u8  comm[TASK_COMM_LEN];
};
// Force BTF emission of struct event so bpf2go -type event can generate it.
struct event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MiB, page-multiple power of two
} events SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(prov_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return ret; // never block on provenance pressure
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return ret; // OBSERVE-ONLY: honor the incoming verdict
}
