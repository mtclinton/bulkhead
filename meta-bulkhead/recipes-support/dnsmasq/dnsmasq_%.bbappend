# SPDX-License-Identifier: AGPL-3.0-only
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# Build dnsmasq with nft-set support (links libnftables) so it can populate the
# bulkhead egress allowlist sets as it resolves api.anthropic.com. OE's default
# PACKAGECONFIG omits nftset, so a stock build ships `no-nftset`.
PACKAGECONFIG:append = " nftset"

# files/dnsmasq.conf (higher FILESEXTRAPATHS priority) replaces OE's default
# /etc/dnsmasq.conf. Add the resolved hand-off + a service drop-in.
SRC_URI += " \
    file://10-bulkhead-dnsmasq.conf \
    file://dnsmasq-bulkhead.conf \
    file://10-bulkhead.network \
"

do_install:append() {
    # OE's dnsmasq-resolved.conf sets DNSStubListener=no, which would remove the
    # resolved stub the agents use; bulkhead keeps the stub and points resolved at
    # dnsmasq:5353 instead.
    rm -f ${D}${sysconfdir}/systemd/resolved.conf.d/dnsmasq-resolved.conf
    install -d ${D}${sysconfdir}/systemd/resolved.conf.d
    install -m0644 ${WORKDIR}/10-bulkhead-dnsmasq.conf \
        ${D}${sysconfdir}/systemd/resolved.conf.d/10-bulkhead-dnsmasq.conf
    install -d ${D}${systemd_system_unitdir}/dnsmasq.service.d
    install -m0644 ${WORKDIR}/dnsmasq-bulkhead.conf \
        ${D}${systemd_system_unitdir}/dnsmasq.service.d/10-bulkhead.conf
    # Don't accept DHCP DNS -> force all resolution through dnsmasq (the allowlist path).
    install -d ${D}${sysconfdir}/systemd/network
    install -m0644 ${WORKDIR}/10-bulkhead.network \
        ${D}${sysconfdir}/systemd/network/10-bulkhead.network
}

FILES:${PN} += " \
    ${sysconfdir}/systemd/resolved.conf.d/10-bulkhead-dnsmasq.conf \
    ${systemd_system_unitdir}/dnsmasq.service.d/10-bulkhead.conf \
    ${sysconfdir}/systemd/network/10-bulkhead.network \
"
