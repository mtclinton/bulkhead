#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# bulkhead PILOT EVALUATION — one command that boots the already-built appliance image and runs the live
# security proofs in critical-path order, then prints a single GO/NO-GO verdict. It demonstrates the four
# pilot legs end-to-end WITHOUT commissioning any hardware:
#   BOOT           a hardened appliance with its security floor live from cold boot
#   SUBMIT+ISOLATE a real agent workload runs in an isolation tier
#   MEDIATE+SIGN   its only egress paths are mediated + every decision signed into the audit chain
#   INJECTION-SAFE a prompt injection in fetched content stays inert (the product thesis)
#   VERIFY-OFFBOX  a fresh-nonce attestation binds the chain HEADs + an off-box monitor catches a rewind
#
# HONESTY: the qemu/swtpm software pilot proves the MECHANISMS above. It does NOT prove hardware-rooted trust —
# EK-rooted attestation (swtpm uses self-signed dev PKI) and PCR-7 measured-boot sealing (the vTPM leaves PCRs
# zeroed) require a commissioned TPM2 target (docs/COMMISSIONING.md). Those are marked [HW-deferred] below and
# in the verdict; the pilot never claims them.
#
# Usage:
#   scripts/pilot-eval.sh            # the full pilot suite (core + the /dev/kvm arms if this host has KVM)
#   scripts/pilot-eval.sh --list     # print the plan + exit (no boots)
#   scripts/pilot-eval.sh <target>…  # run only these make targets (a subset / re-run one leg)
# Each verify-* target boots its OWN qemu (minutes); the suite runs them SEQUENTIALLY (two qemus contend).
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"

# target|LEG|what-it-proves  (ordered = the pilot critical path)
CORE='verify-hbd|BOOT|hardened appliance boots with its security floor LIVE from cold boot (BPF-LSM E0+E2 armed after a reboot)
verify-runsc-unit|SUBMIT+ISOLATE|a real agent workload runs in the gVisor default tier via the deployable systemd path; both mediated legs work; egress signed; bundle reaped
verify-confined-agent|MEDIATE+SIGN|the agent only exits via audited channels: an allowlisted fetch is mediated+signed, a non-allowlisted one is DENIED and the deny is signed
verify-quarantine|INJECTION-SAFE|a prompt injection in fetched content stays inert — control flow fixed before untrusted bytes are read, no privileged tool fires (the product thesis)
verify-attest|VERIFY-OFFBOX|a fresh-nonce TPM-quoted attestation binds the three chain HEADs; rewind/tamper fails closed  [HW-deferred: EK-rooted trust + PCR-7 sealing need a real TPM2]
verify-chain-monitor-live|VERIFY-OFFBOX|the off-box monitor pins the chain HEAD and catches a tail-truncation/rewind within one interval'

KVM='verify-runsc-kvm-nonroot|ISOLATE(+KVM)|non-root in-sandbox uid: setuid/capset CONTAINED yet the agent still reaches its mediated legs (real KVM)
verify-runsc-kvm-escape|ISOLATE(+KVM)|host-surface collapse under runsc --platform=kvm: every host-crossing escape vector contained (real KVM)
verify-fc-jailer|ISOLATE(+KVM)|the Firecracker hostile tier jailer: the VMM runs non-root, chrooted, with no inet socket (real KVM)'

field() { printf '%s\n%s\n' "$CORE" "$KVM" | awk -F'|' -v t="$1" -v n="$2" '$1==t{print $n; f=1} END{if(!f){if(n==2)print "STEP"; else print "(ad-hoc target)"}}'; }
leg_of()   { field "$1" 2; }
prove_of() { field "$1" 3; }

LISTONLY=0
if [ "${1:-}" = "--list" ]; then LISTONLY=1; shift; fi
if [ "$#" -gt 0 ]; then
	TARGETS="$*"
else
	TARGETS="$(printf '%s\n' "$CORE" | cut -d'|' -f1)"
	[ -e /dev/kvm ] && TARGETS="$TARGETS $(printf '%s\n' "$KVM" | cut -d'|' -f1)"
fi

echo "=== bulkhead PILOT EVALUATION ==="
echo "repo: $REPO"
[ -e /dev/kvm ] && echo "host: /dev/kvm present (KVM-tier arms included)" || echo "host: no /dev/kvm (KVM-tier arms skipped — pure software eval)"
echo "plan (critical-path order):"
for t in $TARGETS; do printf '  [%-14s] %s\n        %s\n' "$(leg_of "$t")" "$t" "$(prove_of "$t")"; done
echo
[ "$LISTONLY" = 1 ] && { echo "(--list: nothing run)"; exit 0; }

# The sequential VM boots have tight per-step timeouts; on a LOADED host the software-emulated arms time out
# and the verdict flakes (not a regression). Warn so the evaluator runs it on a quiet/dedicated host.
LOAD1="$(cut -d' ' -f1 /proc/loadavg 2>/dev/null || echo 0)"
NCPU="$(nproc 2>/dev/null || echo 1)"
awk -v l="$LOAD1" -v n="$NCPU" 'BEGIN{ if (l+0 > n+0) printf "WARNING: host 1-min load %.1f exceeds %d CPUs — the software-emulated arms may time out and flake. Run on a quieter/dedicated host for a reliable verdict (the /dev/kvm arms are load-tolerant).\n\n", l, n }'

# Each arm boots its own qemu (software-emulated unless it uses /dev/kvm) with tight per-step timeouts, so under
# host load an arm can FLAKE (e.g. a slirp fetch hitting a context-deadline) without any regression. run_arm
# retries a failed arm ONCE after a settle — a genuinely-broken arm still fails twice => a real FAIL. It does
# NOT pkill qemu/swtpm: on a shared host that would kill unrelated VMs, and each verify-* reaps its own qemu.
run_arm() {
	t="$1"
	( cd "$REPO" && make "$t" ) && return 0
	echo ">>> $t failed once; settling 15s then retrying ONCE (qemu arms flake under host load)..."
	sleep 15
	( cd "$REPO" && make "$t" )
}

PASS=0; FAIL=0; RESULTS=""
for t in $TARGETS; do
	leg="$(leg_of "$t")"
	echo "============================================================"
	echo ">>> [$leg] make $t"
	echo ">>> proves: $(prove_of "$t")"
	echo "============================================================"
	if run_arm "$t"; then
		echo "<<< $t: PASS"; PASS=$((PASS + 1)); RESULTS="$RESULTS
  PASS  [$leg] $t"
	else
		echo "<<< $t: FAIL (twice — not a transient flake)"; FAIL=$((FAIL + 1)); RESULTS="$RESULTS
  FAIL  [$leg] $t"
	fi
done

# --- the pilot-facing verdict renderer: roll the technical arms up into plain-language SECURITY ASSURANCES an
# evaluator (not a cryptographer) can act on. Each assurance's status is derived from the arms in its leg(s):
# all-pass => PASS, any-fail => PARTIAL/FAIL, none-run => n/a. No stdout re-parsing — it reads the same
# structured RESULTS the per-arm table is built from.
acount() { printf '%s\n' "$RESULTS" | grep -cF "$1  [$2]"; }  # <PASS|FAIL> <leg> -> matching arm count
assess() {
	claim="$1"; shift
	p=0; f=0
	for lg in "$@"; do p=$((p + $(acount PASS "$lg"))); f=$((f + $(acount FAIL "$lg"))); done
	if   [ $((p + f)) -eq 0 ]; then st="  n/a  "
	elif [ "$f" -eq 0 ];       then st=" PASS  "
	elif [ "$p" -eq 0 ];       then st=" FAIL  "
	else                            st="PARTIAL"; fi
	printf '  [%s] %s\n' "$st" "$claim"
}

echo
echo "============================================================"
echo "=== PILOT EVALUATION VERDICT ==="
echo "  --- evidence (per check) ---"
printf '%s\n' "$RESULTS"
echo
echo "  --- ASSURANCE SUMMARY — what a passing run means for an evaluator ---"
assess "Hardened boot — the security floor is enforced from cold boot: no operator action, no unarmed window." BOOT
assess "Workload isolation — untrusted agent code is contained: a host-surface-collapsed sandbox, no privilege escalation, resource-bounded." "SUBMIT+ISOLATE" "ISOLATE(+KVM)"
assess "Mediated + signed egress — the agent's only network paths are mediated + allowlist-enforced, and every decision is signed into a tamper-evident log." "MEDIATE+SIGN"
assess "Injection safety — a prompt injection in fetched content cannot trigger a privileged action (the product thesis)." "INJECTION-SAFE"
assess "Off-box verifiability — an external party can cryptographically verify the appliance's posture and detect any audit-log rewind/truncation." "VERIFY-OFFBOX"
echo
echo "  [HW-deferred] NOT proven by this software pilot (need a commissioned TPM2 target — docs/COMMISSIONING.md):"
echo "      - EK-rooted attestation (swtpm uses self-signed dev PKI, not a genuine manufacturer EK cert)"
echo "      - PCR-7 measured-boot sealing of the audit seed + MITM CA (the qemu vTPM leaves PCRs zeroed)"
echo
if [ "$FAIL" -eq 0 ]; then
	echo "=== PILOT GO — $PASS/$((PASS + FAIL)) checks proven on this host (software pilot) ==="
	exit 0
else
	echo "=== PILOT NO-GO — $FAIL of $((PASS + FAIL)) checks FAILED ==="
	exit 1
fi
