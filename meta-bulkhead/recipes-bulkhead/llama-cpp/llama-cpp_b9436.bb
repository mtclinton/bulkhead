# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "llama.cpp inference server (llama-server)"
HOMEPAGE = "https://github.com/ggml-org/llama.cpp"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=223b26b3c1143120c87e2b13111d3e99"

SRC_URI = "git://github.com/ggml-org/llama.cpp.git;protocol=https;branch=master;destsuffix=git"
SRCREV = "d6588daa800058dfa54f1d7ea695b1a810c8ae18"
PV = "b9436+git"
S = "${WORKDIR}/git"

inherit cmake

# The server's bundled httplib enables TLS when it finds OpenSSL; declare it so we
# link the target openssl and the image ships libssl/libcrypto (RAUC/curl need it too).
DEPENDS += "openssl"
RDEPENDS:${PN} += "openssl"

# Portable build (no -march=native -> safe under any qemu CPU); no curl/openmp;
# server only; static (one binary), matching the v1 prototype.
EXTRA_OECMAKE = " \
    -DGGML_NATIVE=OFF \
    -DGGML_OPENMP=OFF \
    -DLLAMA_CURL=OFF \
    -DLLAMA_BUILD_SERVER=ON \
    -DLLAMA_BUILD_TOOLS=ON \
    -DLLAMA_BUILD_TESTS=OFF \
    -DLLAMA_BUILD_EXAMPLES=OFF \
    -DBUILD_SHARED_LIBS=OFF \
"

do_install:append() {
	# Ship only the inference server. The other tools (e.g. llama-tts) pull in
	# openssl and we don't use them — dropping them keeps the image lean and
	# avoids an unneeded libssl/libcrypto runtime dependency.
	find ${D}${bindir} -maxdepth 1 -type f ! -name 'llama-server' -delete
}

FILES:${PN} += "${bindir}/llama-server"
