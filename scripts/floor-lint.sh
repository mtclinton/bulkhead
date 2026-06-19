#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Build-time SECURITY-FLOOR LINT. Many load-bearing structural invariants are required by the ADRs but had NO
# automated guard — a future edit could silently weaken them (PRODUCTION-READINESS [6]/[126]; the
# io-uring-jail-deny + unix-socket-af-unix lessons). This is a fast static guard (no qemu / no hardware) that
# fails the build on any such regression, and carries its own negative self-test (`--selftest`) — a lint that
# cannot fail is worthless, so it injects a regression per invariant into a throwaway tree and asserts a catch.
#
# Adversarially reviewed 2026-06-19: the seccomp checks are DROP-IN aware and reset/re-allow aware (systemd
# MERGES SystemCallFilter= additively across the base unit + its .d/*.conf drop-ins, and a bare
# `SystemCallFilter=` RESETS the whole list), and jails are discovered DYNAMICALLY so a new one is covered.
set -u

ROOT="."; SELFTEST=0
for a in "$@"; do case "$a" in --root=*) ROOT="${a#--root=}" ;; --selftest) SELFTEST=1 ;; esac; done
OV="$ROOT/external/board/bulkhead/rootfs-overlay/etc/systemd/system"
NFT="$ROOT/external/board/bulkhead/rootfs-overlay/etc/nftables.conf"
RUNSC="$ROOT/external/board/bulkhead/rootfs-overlay/usr/bin/bulkhead-agent-runsc-launch"
YCFG="$ROOT/meta-bulkhead/recipes-kernel/linux/files/bulkhead-security.cfg"
BRFRAG="$ROOT/external/board/bulkhead/linux-bulkhead.fragment"
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
has() { grep -qE -- "$2" "$1" 2>/dev/null; }   # `--` so a pattern starting with `-` (e.g. --network=none) is not parsed as a grep option

SIB="@resources @privileged @obsolete @cpu-emulation @mount @reboot @swap @raw-io @module"
IOURING="io_uring_setup io_uring_enter io_uring_register"

# the base unit file + every .d/*.conf drop-in systemd would merge (template per-instance dirs included).
unit_and_dropins() {
	printf '%s\n' "$OV/$1"
	case "$1" in
		*@.service) ls "$OV/${1%@.service}"@*.service.d/*.conf 2>/dev/null ;;
		*)          ls "$OV/${1%.service}".service.d/*.conf 2>/dev/null ;;
	esac
}

# check_seccomp_deny <unit> <token...>: every token is DENIED on a `~` line AND the deny is not undone — no
# bare `SystemCallFilter=` reset and no non-`~` additive line that re-adds a guarded token — across the base
# unit AND its drop-ins. All whitespace (incl. tabs) is normalized so a valid reformat does not false-alarm.
check_seccomp_deny() {
	u="$1"; shift
	scf=$(grep -hE '^SystemCallFilter=' $(unit_and_dropins "$u") 2>/dev/null)
	deny=" $(printf '%s\n' "$scf" | grep -E '^SystemCallFilter=~' | sed 's/^SystemCallFilter=~//' | tr '\t' ' ' | tr -s ' ') "
	for t in "$@"; do case "$deny" in *" $t "*) ;; *) return 1 ;; esac; done
	undo=0; oldIFS=$IFS; IFS='
'
	for ln in $scf; do
		val=${ln#SystemCallFilter=}
		[ -z "$val" ] && { undo=1; continue; }   # a bare reset clears the whole filter
		case "$val" in '~'*) continue ;; esac    # a deny (subtract) line is fine
		p=" $(printf '%s' "$val" | tr '\t' ' ' | tr -s ' ') "
		for t in "$@"; do case "$p" in *" $t "*) undo=1 ;; esac; done   # a non-~ line re-allowing a guarded token
	done
	IFS=$oldIFS
	[ "$undo" -eq 0 ]
}

lint() {
	# (1) ADR-0033: every SECCOMP-tier agent jail must deny io_uring BY NAME (@system-service permits it via
	# @aio). DYNAMIC discovery — any bulkhead-agent*@.service whose filter is @system-service-based; the
	# runsc/Firecracker tiers carry no @system-service (io_uring is structurally ENOSYS / compiled out), so the
	# filter auto-excludes them and a NEW seccomp jail is covered by default.
	for f in "$OV"/bulkhead-agent*@.service; do
		[ -e "$f" ] || continue
		has "$f" '^SystemCallFilter=@system-service' || continue
		u=$(basename "$f")
		if check_seccomp_deny "$u" $IOURING; then ok "seccomp jail denies io_uring by name (drop-in/reset aware): $u"; else bad "seccomp jail does NOT effectively deny io_uring: $u"; fi
	done

	# (2) ADR-0033 amendment: io_uring compiled OUT of the kernel in BOTH fragments (the FC guest extracts it);
	# inert without CONFIG_EXPERT=y (EXPERT-gated), and a stray CONFIG_IO_URING=y would re-enable it.
	for f in "$YCFG" "$BRFRAG"; do
		b=$(basename "$f")
		if grep -qE '^# CONFIG_IO_URING is not set' "$f" && grep -qE '^CONFIG_EXPERT=y' "$f" && ! grep -qE '^CONFIG_IO_URING=y' "$f"; then
			ok "kernel io_uring compiled out + EXPERT-gated: $b"
		else bad "kernel io_uring not effectively disabled: $b"; fi
	done

	# (3) ADR-0042: the Firecracker host mux floor is a strict SUPERSET of the egress-proxy/router siblings.
	MUX="bulkhead-fc-vsockmux@.service"
	if check_seccomp_deny "$MUX" $SIB $IOURING; then ok "mux deny set is a superset of the sibling floor + io_uring"; else bad "mux deny set is NOT a superset of the sibling floor"; fi
	for d in PrivateDevices=yes RestrictRealtime=yes RestrictSUIDSGID=yes MemoryDenyWriteExecute=yes; do
		has "$OV/$MUX" "^$d\$" && ok "mux extra lock: $d" || bad "mux missing extra lock: $d"
	done

	# (4) the mediation-fabric units empty CapabilityBoundingSet + NoNewPrivileges + ProtectSystem=strict + the
	# sibling deny set. (The collector is excluded — as the BPF-LSM enforcer it legitimately holds caps, ADR-0041.)
	for u in bulkhead-egress-proxy.service bulkhead-router.service bulkhead-fc-vsockmux@.service; do
		f="$OV/$u"
		if has "$f" '^CapabilityBoundingSet=$' && has "$f" '^NoNewPrivileges=yes' && has "$f" '^ProtectSystem=strict' && check_seccomp_deny "$u" $SIB; then
			ok "mediation hardening floor: $u"
		else bad "mediation hardening floor incomplete (empty caps + NoNewPrivileges + ProtectSystem=strict + sibling deny): $u"; fi
	done

	# (5) the structural nftables egress floor: BOTH filter chains are `policy drop`, and no `policy accept`
	# (holds regardless of BPF E2 enforce state — security-review R-floor).
	if [ "$(grep -cE 'hook input .*policy drop' "$NFT" 2>/dev/null)" -ge 1 ] && [ "$(grep -cE 'hook output .*policy drop' "$NFT" 2>/dev/null)" -ge 1 ] \
	   && ! grep -vE '^[[:space:]]*#' "$NFT" 2>/dev/null | grep -qE 'policy accept'; then
		ok "nftables: input + output chains are policy drop (no policy accept)"
	else bad "nftables default-deny floor weakened (need input+output policy drop, no policy accept)"; fi

	# (6) the unix-socket-af-unix lesson (a SHIPPED crash-loop): UDS-serving TCB units must list AF_UNIX, and
	# the AF_UNIX-only units (mux, broker) must hold NO AF_INET/AF_INET6 (collector/router/egress legitimately do).
	for u in bulkhead-router.service bulkhead-egress-proxy.service bulkhead-fc-vsockmux@.service bulkhead-broker.service bulkhead-collector.service; do
		has "$OV/$u" '^RestrictAddressFamilies=.*AF_UNIX' && ok "AF_UNIX present: $u" || bad "RestrictAddressFamilies missing AF_UNIX (crash-loop risk): $u"
	done
	for u in bulkhead-fc-vsockmux@.service bulkhead-broker.service; do
		if grep -E '^RestrictAddressFamilies=' "$OV/$u" 2>/dev/null | grep -qE 'AF_INET'; then bad "AF_UNIX-only unit holds AF_INET: $u"; else ok "AF_UNIX-only (no AF_INET): $u"; fi
	done

	# (7) ADR-0031: the runsc launcher's OCI invariants (mirror fc-image-check for the runsc tier).
	for tok in -- '--network=none' '--host-uds=open' '"bounding":\[\]' '"readonly":true'; do
		[ "$tok" = "--" ] && continue
		has "$RUNSC" "$tok" && ok "runsc launcher: $tok" || bad "runsc launcher missing: $tok"
	done
	has "$RUNSC" '\-\-network=host' && bad "runsc launcher has --network=host (direct egress!)" || ok "runsc launcher never uses --network=host"

	# (8) security-review R1: the fail-closed selftest gate must be a Requires= edge (propagates failure) on the
	# chokepoints — not a mere After=/Wants= (which would let web egress run while the TCB refused).
	for u in bulkhead-egress-proxy.service bulkhead-router.service bulkhead-collector.service bulkhead-agent-firecracker@.service; do
		has "$OV/$u" '^Requires=.*bulkhead-selftest' && ok "Requires= selftest gate: $u" || bad "missing Requires=bulkhead-selftest (fail-closed edge): $u"
	done

	# (9) ADR-0034 inc1: the confined agent's no-route netns is THE structural egress boundary.
	has "$OV/bulkhead-agent-confined@.service" '^PrivateNetwork=yes' && ok "confined jail: PrivateNetwork=yes" || bad "confined jail lost PrivateNetwork=yes (egress boundary)"

	# (10) the cgroup/skb egress floor (loopback-only) on the agent slice + base template.
	for u in bulkhead-agent.slice bulkhead-agent@.service; do
		has "$OV/$u" '^IPAddressDeny=any' && ok "IPAddressDeny=any: $u" || bad "missing IPAddressDeny=any: $u"
	done
}

lint
echo
echo "=== security-floor lint: $PASS passed, $FAIL failed ==="
verdict=0; [ "$FAIL" -eq 0 ] || verdict=1

# ---- negative self-test: prove each invariant's check FAILS on a regression ----------------------------
if [ "$SELFTEST" -eq 1 ]; then
	echo; echo "--- self-test (inject a regression; the lint MUST catch each, and each injection MUST mutate the tree) ---"
	SP=0; SF=0
	sok()  { echo "PASS: $1"; SP=$((SP + 1)); }
	sbad() { echo "FAIL: $1"; SF=$((SF + 1)); }
	stage() { # a throwaway tree copy of every file the lint reads (drop-in .d dirs included)
		t=$(mktemp -d)
		mkdir -p "$t/external/board/bulkhead/rootfs-overlay/etc/systemd/system" \
		         "$t/external/board/bulkhead/rootfs-overlay/usr/bin" \
		         "$t/meta-bulkhead/recipes-kernel/linux/files"
		cp -r "$OV"/. "$t/external/board/bulkhead/rootfs-overlay/etc/systemd/system/"
		cp "$NFT" "$t/external/board/bulkhead/rootfs-overlay/etc/nftables.conf" 2>/dev/null
		cp "$RUNSC" "$t/external/board/bulkhead/rootfs-overlay/usr/bin/bulkhead-agent-runsc-launch" 2>/dev/null
		cp "$YCFG" "$t/meta-bulkhead/recipes-kernel/linux/files/bulkhead-security.cfg"
		cp "$BRFRAG" "$t/external/board/bulkhead/linux-bulkhead.fragment"
		echo "$t"
	}
	catches() { # <desc> <staged-tree>: run the lint on the mutated tree, expect FAIL
		if sh "$0" --root="$2" >/dev/null 2>&1; then sbad "lint did NOT catch: $1"; else sok "lint catches: $1"; fi
		rm -rf "$2"
	}
	neg() { # <desc> <relpath> <sed-expr>: mutate via sed, assert it actually CHANGED the file (no vacuous pass)
		t=$(stage); cp "$t/$2" "$t/$2.orig"; sed "$3" "$t/$2.orig" > "$t/$2"
		if cmp -s "$t/$2" "$t/$2.orig"; then sbad "SELFTEST no-op (regression not injected): $1"; rm -rf "$t"; return; fi
		rm -f "$t/$2.orig"; catches "$1" "$t"
	}
	U="external/board/bulkhead/rootfs-overlay/etc/systemd/system"
	D="external/board/bulkhead/rootfs-overlay/etc"
	# soundness regressions (the adversarial review's confirmed evasions)
	neg "seccomp jail dropping the io_uring deny" "$U/bulkhead-agent@.service" "s/$IOURING//"
	t=$(stage); printf '%s\n' 'SystemCallFilter=io_uring_setup io_uring_enter io_uring_register' >> "$t/$U/bulkhead-agent@.service"; catches "additive re-allow line restoring io_uring" "$t"
	t=$(stage); printf '%s\n' 'SystemCallFilter=' >> "$t/$U/bulkhead-agent@.service"; catches "bare SystemCallFilter= reset clearing the floor" "$t"
	t=$(stage); mkdir -p "$t/$U/bulkhead-agent@evil.service.d"; printf '[Service]\nSystemCallFilter=\n' > "$t/$U/bulkhead-agent@evil.service.d/99-reset.conf"; catches "drop-in resetting an instance's seccomp filter" "$t"
	t=$(stage); sed "s/$IOURING//" "$t/$U/bulkhead-agent@.service" > "$t/$U/bulkhead-agent-hostile@.service"; catches "NEW seccomp jail (other name) missing the io_uring deny" "$t"
	# new-invariant regressions
	neg "kernel fragment re-enabling io_uring" "meta-bulkhead/recipes-kernel/linux/files/bulkhead-security.cfg" 's/^# CONFIG_IO_URING is not set/CONFIG_IO_URING=y/'
	neg "kernel fragment losing EXPERT (disable goes inert)" "external/board/bulkhead/linux-bulkhead.fragment" 's/^CONFIG_EXPERT=y/# CONFIG_EXPERT is not set/'
	neg "mux dropping a sibling deny token (@resources)" "$U/bulkhead-fc-vsockmux@.service" 's/@resources //'
	neg "mux dropping PrivateDevices" "$U/bulkhead-fc-vsockmux@.service" '/^PrivateDevices=yes/d'
	neg "mediation unit un-emptying CapabilityBoundingSet" "$U/bulkhead-router.service" 's/^CapabilityBoundingSet=$/CapabilityBoundingSet=CAP_NET_ADMIN/'
	neg "mediation unit losing ProtectSystem=strict" "$U/bulkhead-router.service" '/^ProtectSystem=strict/d'
	neg "nftables output chain flipped to policy accept" "$D/nftables.conf" 's/hook output priority 0; policy drop;/hook output priority 0; policy accept;/'
	neg "AF_UNIX-only mux gaining AF_INET" "$U/bulkhead-fc-vsockmux@.service" 's/^RestrictAddressFamilies=AF_UNIX$/RestrictAddressFamilies=AF_UNIX AF_INET/'
	neg "router losing AF_UNIX (crash-loop)" "$U/bulkhead-router.service" 's/^RestrictAddressFamilies=.*/RestrictAddressFamilies=AF_INET AF_INET6/'
	neg "runsc launcher switched to --network=host" "external/board/bulkhead/rootfs-overlay/usr/bin/bulkhead-agent-runsc-launch" 's/--network=none/--network=host/'
	neg "chokepoint downgrading Requires=selftest to After=" "$U/bulkhead-egress-proxy.service" '/bulkhead-selftest/s/^Requires=/After=/'
	neg "confined jail dropping PrivateNetwork" "$U/bulkhead-agent-confined@.service" '/^PrivateNetwork=yes/d'
	neg "agent slice dropping IPAddressDeny" "$U/bulkhead-agent.slice" '/^IPAddressDeny=any/d'
	echo; echo "=== self-test: $SP passed, $SF failed ==="
	[ "$SF" -eq 0 ] || verdict=1
fi

[ "$verdict" -eq 0 ] && echo "FLOOR LINT GO" || echo "FLOOR LINT FAIL"
exit "$verdict"
