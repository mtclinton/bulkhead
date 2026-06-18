# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead Firecracker hostile-tier guest kernel (ELF vmlinux, ADR-0042/0031)"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/GPL-2.0-only;md5=801f80980d171dd6425610833a22dbe6"

# Firecracker boots an uncompressed ELF vmlinux, NOT the gzip'd bzImage ("Invalid Elf magic number"). This
# extracts vmlinux from the appliance kernel's deploy bzImage at BUILD time (the same extraction the
# ADR-0031 spike + ADR-0042 slices did at runtime) and ships it at /usr/share/bulkhead/fc/vmlinux for the
# firecracker launcher. The hostile-tier guest reuses the appliance kernel, which now has io_uring
# COMPILED OUT (CONFIG_IO_URING off in the shared bulkhead-security fragment, ADR-0033 amendment) — so the
# guest inherits no in-VM io_uring (verify-firecracker-agent's IOURING probe sees ENOSYS). The remaining
# FC-tuning item, dropping CONFIG_VIRTIO_NET, is deferred: it needs a SEPARATE guest kernel (un-boot-testable
# without nested KVM) for marginal gain, since no-NIC already rests structurally on omitting the firecracker
# network stanza, not the kernel.
DEPENDS = "virtual/kernel"
do_compile[depends] += "virtual/kernel:do_deploy"

S = "${WORKDIR}"
COMPATIBLE_MACHINE = "qemux86-64"
INHIBIT_DEFAULT_DEPS = "1"

do_compile() {
	# Find the gzip member inside the bzImage and inflate it; the result is the ELF vmlinux.
	python3 - "${DEPLOY_DIR_IMAGE}/bzImage" "${B}/vmlinux" <<'PYEOF'
import sys, zlib, re
data = open(sys.argv[1], 'rb').read()
best = None
# Scan every gzip member (magic 1f 8b 08; the kernel's payload is CONFIG_KERNEL_GZIP) and inflate each.
# Accept ONLY a COMPLETE stream: d.eof True means the gzip CRC/ISIZE trailer was consumed, so a truncated or
# corrupt bzImage can't silently yield a partial vmlinux with a valid ELF header but a missing tail (which
# would only fail to boot on real hardware, where it is hardest to debug). Keep the LARGEST qualifying ELF
# member, robust to any other embedded gzip blob being scanned first.
for m in re.finditer(b'\x1f\x8b\x08', data):
    d = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        out = d.decompress(data[m.start():]) + d.flush()
    except Exception:
        continue
    if d.eof and out[:4] == b'\x7fELF' and len(out) > 1_000_000:
        if best is None or len(out) > len(best):
            best = out
if best is None:
    sys.exit('bulkhead-fc-guestkernel: no COMPLETE ELF vmlinux found in bzImage (truncated/corrupt deploy image?)')
open(sys.argv[2], 'wb').write(best)
PYEOF
}

do_install() {
	install -Dm0644 ${B}/vmlinux ${D}${datadir}/bulkhead/fc/vmlinux
}

# The extracted vmlinux is the kernel's own (already-stripped) ELF; it is a boot payload, not a debuggable
# package binary, so QA's strip check does not apply (same posture as the prebuilt firecracker binaries).
INSANE_SKIP:${PN} += "already-stripped"
FILES:${PN} = "${datadir}/bulkhead/fc/vmlinux"
