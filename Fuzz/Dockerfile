# Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Linux build+run environment for KDBXKit's libFuzzer fuzz targets.
#
# Building libFuzzer targets on macOS is too fragile (the Xcode toolchain
# cannot do -sanitize=fuzzer at all; the swift.org toolchain needs a C
# entry-point stub + dlsym + release-only + ld workarounds). On Linux/ELF the
# libFuzzer runtime supplies main cleanly, so the fuzzers build and run here.
#
# This image is just the toolchain + zlib headers; the source tree is
# bind-mounted at runtime by Fuzz/run-fuzz.sh (so the image never goes stale
# and the on-disk corpus/crashers are read and written in place). The actual
# build recipe lives in run-fuzz.sh, not here.
#
# Pinned to the same Swift 6.1 image the CI Linux lane uses
# (see scripts/test-linux.sh). 6.1-jammy resolves to Swift 6.1.3.
FROM swift:6.1-jammy

# zlib1g-dev: the CZlib system-library target needs the zlib headers + libz to
# link the inner-payload gzip path. clang ships with the Swift toolchain and
# already carries the libFuzzer + ASan runtimes, so nothing else is required.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
