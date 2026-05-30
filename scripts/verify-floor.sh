#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Assert the bulkhead kernel security floor is live. Run INSIDE the booted guest.
#
# This checks that the floor EXISTS. It does not replace the runtime boot
# self-test (M5), which actively attempts forbidden actions and requires them to
# be denied. Both matter: config can lie, so the self-test is the binding gate.
set -u
fail=0
pass() { echo "PASS: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else bad "$1"; fi; }

lsm="$(cat /sys/kernel/security/lsm 2>/dev/null || echo '')"
echo "active LSMs: ${lsm:-<none>}"

check "BPF-LSM active"                "echo '$lsm' | tr ',' '\n' | grep -qx bpf"
check "Landlock active"               "echo '$lsm' | tr ',' '\n' | grep -qx landlock"
check "kernel BTF present (CO-RE)"    "test -r /sys/kernel/btf/vmlinux"
check "cgroup v2 unified hierarchy"   "test -e /sys/fs/cgroup/cgroup.controllers"
check "cgroup BPF egress firewall"    "zcat /proc/config.gz 2>/dev/null | grep -qx 'CONFIG_CGROUP_BPF=y'"
check "seccomp filter"                "zcat /proc/config.gz 2>/dev/null | grep -qx 'CONFIG_SECCOMP_FILTER=y'"
check "TPM device present"            "test -e /dev/tpmrm0 -o -e /dev/tpm0"

if [ "$fail" -eq 0 ]; then echo "FLOOR OK"; else echo "FLOOR INCOMPLETE"; fi
exit "$fail"
