################################################################################
# SPDX-License-Identifier: AGPL-3.0-only
# llama-cpp — llama.cpp inference server for the bulkhead local tier
################################################################################

LLAMA_CPP_VERSION = b9436
LLAMA_CPP_SITE = $(call github,ggml-org,llama.cpp,$(LLAMA_CPP_VERSION))
LLAMA_CPP_LICENSE = MIT
LLAMA_CPP_LICENSE_FILES = LICENSE

# Portable build: GGML_NATIVE=OFF so the binary does not bake in the build
# host's -march=native (it would SIGILL under a different qemu -cpu). No curl,
# so the binary never attempts network model downloads (default-deny egress).
LLAMA_CPP_CONF_OPTS = \
	-DGGML_NATIVE=OFF \
	-DGGML_OPENMP=OFF \
	-DLLAMA_CURL=OFF \
	-DLLAMA_BUILD_SERVER=ON \
	-DLLAMA_BUILD_TOOLS=ON \
	-DLLAMA_BUILD_TESTS=OFF \
	-DLLAMA_BUILD_EXAMPLES=OFF \
	-DBUILD_SHARED_LIBS=OFF

$(eval $(cmake-package))
