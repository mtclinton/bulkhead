# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead Firecracker hostile-tier guest kernel (ELF vmlinux, ADR-0042/0031)"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/GPL-2.0-only;md5=801f80980d171dd6425610833a22dbe6"

# Firecracker boots an uncompressed ELF vmlinux, NOT the gzip'd bzImage ("Invalid Elf magic number"). This
# extracts vmlinux from the appliance kernel's deploy bzImage at BUILD time (the same extraction the
# ADR-0031 spike + ADR-0042 slices did at runtime) and ships it at /usr/share/bulkhead/fc/vmlinux for the
# firecracker launcher. The hostile-tier guest reuses the appliance kernel for now; a firecracker-TUNED
# guest kernel (io_uring disabled per ADR-0033, CONFIG_VIRTIO_NET dropped for defense-in-depth) is a
# follow-up — the no-NIC guarantee already rests on omitting the firecracker network stanza, not the kernel.
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
for m in re.finditer(b'\x1f\x8b\x08', data):
    try:
        out = zlib.decompressobj(zlib.MAX_WBITS | 16).decompress(data[m.start():])
    except Exception:
        continue
    if out[:4] == b'\x7fELF' and len(out) > 1_000_000:
        open(sys.argv[2], 'wb').write(out)
        sys.exit(0)
sys.exit('bulkhead-fc-guestkernel: no ELF vmlinux found in bzImage')
PYEOF
}

do_install() {
	install -Dm0644 ${B}/vmlinux ${D}${datadir}/bulkhead/fc/vmlinux
}

FILES:${PN} = "${datadir}/bulkhead/fc/vmlinux"
