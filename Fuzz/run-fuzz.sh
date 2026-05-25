#!/usr/bin/env bash
#
# Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Build and run a KDBXKit libFuzzer campaign inside a Linux container.
#
# Usage:
#   Fuzz/run-fuzz.sh <header|parse|xml|variantdict|blockstream> [seconds]
#
# Default duration is 60s. The repo is bind-mounted into the container; the
# on-disk Fuzz/corpus/<target>/ is used as the corpus (read + grown in place)
# and any crasher is written to Fuzz/crashers/<target>/. For header/parse the
# corpus is seeded (idempotently) from the bundled *.kdbx test fixtures first.
#
# WHY DOCKER / WHY THIS RECIPE
# ----------------------------
# macOS cannot build these targets cleanly. On Linux the libFuzzer runtime
# supplies `main`, so we build there. SwiftPM still can't link the fuzz
# executableTargets directly: their `-parse-as-library` suppresses the
# `<Target>_main` symbol SwiftPM's executable wrapper references, so the
# package link fails with `undefined symbol 'FuzzHeader_main'` even on Linux.
#
# So we sidestep SwiftPM's executable linking entirely (option B):
#   1. `swift build -c release -Xswiftc -enable-testing` WITHOUT KDBXKIT_FUZZ
#      (so the fuzz executableTargets are not even declared -> clean build of
#      KDBXKit + all its deps). -enable-testing is included so the recipe also
#      works for the future @testable inner targets (FuzzXML/VariantDict/
#      BlockStream); the public targets do not need it but it is harmless.
#   2. Compile the single harness main.swift to an object with
#      `swiftc -c -sanitize=fuzzer` (libFuzzer coverage instrumentation),
#      pointing at the built KDBXKit .swiftmodule and the C module maps for the
#      argon2 and CZlib targets.
#   3. Link with the swiftc driver and `-sanitize=fuzzer` (which pulls in the
#      libFuzzer runtime + its main), feeding it the harness object plus every
#      dependency object SwiftPM already produced for the `kdbx` executable
#      (reusing kdbx.product/Objects.LinkFileList), minus the CLI-only targets.
#
# This is intentionally driven from a plain shell recipe rather than a SwiftPM
# product so it survives toolchain changes to how executables are linked.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    echo "Usage: $0 <header|parse|xml|variantdict|blockstream> [seconds]" >&2
    exit 2
}

[ "$#" -ge 1 ] || usage
TARGET_KEY="$1"
SECONDS_TO_RUN="${2:-60}"

# Map the friendly key to the SwiftPM target / harness directory name.
case "$TARGET_KEY" in
    header)      TARGET="FuzzHeader" ;;
    parse)       TARGET="FuzzParse" ;;
    xml)         TARGET="FuzzXML" ;;
    variantdict) TARGET="FuzzVariantDict" ;;
    blockstream) TARGET="FuzzBlockStream" ;;
    *)           echo "error: unknown target '$TARGET_KEY'" >&2; usage ;;
esac

case "$SECONDS_TO_RUN" in
    ''|*[!0-9]*) echo "error: seconds must be a positive integer" >&2; usage ;;
esac

CORPUS_DIR="$REPO_ROOT/Fuzz/corpus/$TARGET_KEY"
CRASHERS_DIR="$REPO_ROOT/Fuzz/crashers/$TARGET_KEY"
mkdir -p "$CORPUS_DIR" "$CRASHERS_DIR"

# Seed the corpus from real KDBX fixtures for the targets that parse whole
# files. Plain copy, idempotent (cp -n never clobbers a grown corpus entry).
if [ "$TARGET_KEY" = "header" ] || [ "$TARGET_KEY" = "parse" ]; then
    shopt -s nullglob
    for f in "$REPO_ROOT"/Tests/KDBXKitTests/Resources/*.kdbx; do
        cp -n "$f" "$CORPUS_DIR/seed-$(basename "$f")"
    done
    shopt -u nullglob
fi

IMAGE="kdbxkit-fuzz"

echo "==> Building Docker image $IMAGE"
docker build -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"

# -t only if attached to a TTY (CI / piped output otherwise fails).
DOCKER_TTY_FLAG=""
[ -t 1 ] && DOCKER_TTY_FLAG="-t"

echo "==> Building + running $TARGET (${SECONDS_TO_RUN}s) in container"

# Everything below runs inside the container. Paths are container paths
# (/workspace == bind-mounted repo). The corpus/crashers dirs are inside the
# same mount, so growth + crashers land back on the host automatically.
docker run --rm -i $DOCKER_TTY_FLAG \
    --platform linux/arm64 \
    -v "$REPO_ROOT":/workspace \
    -w /workspace \
    -e TARGET="$TARGET" \
    -e TARGET_KEY="$TARGET_KEY" \
    -e SECONDS_TO_RUN="$SECONDS_TO_RUN" \
    "$IMAGE" \
    bash -euo pipefail -c '
        # Linux build path kept separate from macOS .build and the CI
        # .build-linux so a container fuzz build never disturbs either.
        BP=.build-fuzz

        echo "--> swift build (release, enable-testing)"
        # No KDBXKIT_FUZZ here: the fuzz executableTargets must NOT be declared
        # or SwiftPM tries (and fails) to link them. We only want the library
        # + dependency objects out of this build.
        swift build -c release --build-path "$BP" -Xswiftc -enable-testing

        REL="$BP/release"
        MODULES="$REL/Modules"
        ARGON2_MM="$(pwd)/$REL/argon2.build/module.modulemap"
        CZLIB_MM="$(pwd)/Sources/CZlib/module.modulemap"

        echo "--> compiling harness $TARGET/main.swift with -sanitize=fuzzer"
        swiftc -c -O \
            -sanitize=fuzzer \
            -parse-as-library \
            -swift-version 6 \
            -I "$MODULES" \
            -Xcc -fmodule-map-file="$ARGON2_MM" \
            -Xcc -fmodule-map-file="$CZLIB_MM" \
            -module-name "${TARGET}Main" \
            "Fuzz/Sources/$TARGET/main.swift" \
            -o /tmp/fuzzharness.o

        echo "--> linking $TARGET libFuzzer driver"
        # Reuse the kdbx executable’s dependency object list (KDBXKit + Crypto +
        # BoringSSL + argon2 + zlib glue + ...), minus the CLI-only targets.
        grep -vE "/(KDBXCLICore|kdbx_cli|ArgumentParser|ArgumentParserToolInfo)\.build/" \
            "$REL/kdbx.product/Objects.LinkFileList" | tr -d "\"" > /tmp/objs.txt

        swiftc \
            -sanitize=fuzzer \
            -O \
            /tmp/fuzzharness.o \
            @/tmp/objs.txt \
            -L "$REL" \
            -lz \
            -o "/tmp/$TARGET"

        echo "--> running $TARGET for ${SECONDS_TO_RUN}s"
        # libFuzzer reads + grows the mounted corpus dir and writes any crasher
        # (crash-* / leak-* / timeout-* / oom-*) under the mounted crashers dir.
        "/tmp/$TARGET" \
            -max_total_time="$SECONDS_TO_RUN" \
            -timeout=10 \
            -rss_limit_mb=2048 \
            -artifact_prefix="Fuzz/crashers/$TARGET_KEY/" \
            "Fuzz/corpus/$TARGET_KEY"
    '

echo "==> $TARGET done. Corpus: Fuzz/corpus/$TARGET_KEY  Crashers: Fuzz/crashers/$TARGET_KEY"
