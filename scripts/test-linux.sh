#!/usr/bin/env bash
#
# Build + test KDBXKit in the same Linux container CI uses.
#
# Usage:
#   ./scripts/test-linux.sh                  # build + test
#   ./scripts/test-linux.sh --filter Header  # forwarded to `swift test`
#
# Environment overrides:
#   SWIFT=6.2           Use a different Swift toolchain.
#   PLATFORM=linux/amd64  Cross-test the x86_64 path (slow under qemu on Apple Silicon).
#
set -euo pipefail

# Resolve repo root so the script works regardless of invocation cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

SWIFT="${SWIFT:-6.1}"
PLATFORM="${PLATFORM:-linux/arm64}"
IMAGE="swift:${SWIFT}-jammy"

# Forward any extra args to `swift test` so callers can do e.g. --filter Header.
EXTRA_TEST_ARGS=("$@")

# Quote-safe re-emit of the test args inside the container's bash -c.
printf -v ESCAPED_TEST_ARGS '%q ' "${EXTRA_TEST_ARGS[@]}"

docker run --rm -it \
  --platform "$PLATFORM" \
  -v "$REPO_ROOT":/workspace \
  -w /workspace \
  "$IMAGE" \
  bash -c "set -euo pipefail
           apt-get update -qq
           apt-get install -y --no-install-recommends zlib1g-dev > /dev/null
           swift --version
           swift build --build-path .build-linux
           swift test --build-path .build-linux ${ESCAPED_TEST_ARGS}"
