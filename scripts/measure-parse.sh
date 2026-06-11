#!/usr/bin/env bash
#
# Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Measure the memory footprint of an EAGER KDBX parse — the exact
# `KDBXReader.parse` path the iOS AutoFill extension runs via
# VaultManager.openContent. Reproduces the AutoFill EXC_RESOURCE (220 MB)
# kill on macOS, with no device and no AutoFill UI, so the fix can be
# iterated against `/usr/bin/time -l` peak footprint.
#
# Usage:
#   printf '%s' 'MASTER_PASSWORD' | scripts/measure-parse.sh /path/vault.kdbx
#
# The password is read once from stdin (never argv / env / shell history).
set -euo pipefail

vault="${1:?usage: measure-parse.sh <vault.kdbx>  (password on stdin)}"
[ -f "$vault" ] || { echo "no such file: $vault" >&2; exit 1; }

IFS= read -r pw || true

echo "==> building release kdbx"
swift build -c release --product kdbx >/dev/null
bin="$(swift build -c release --show-bin-path)/kdbx"

filesize=$(stat -f%z "$vault")
echo
echo "vault file:        $vault"
echo "on-disk size:      $filesize bytes ($((filesize / 1024 / 1024)) MiB)"

# Decompressed XML size + structural counts (full parse, plaintext stays in
# the pipe, never written to disk).
xml=$(printf '%s' "$pw" | "$bin" db xml "$vault" --password-stdin)
echo "decompressed XML:  $(printf '%s' "$xml" | wc -c | tr -d ' ') bytes"
echo "entries:           $(printf '%s' "$xml" | grep -c '<Entry>' || true)"
echo "protected strings: $(printf '%s' "$xml" | grep -c 'Protected=\"True\"' || true)"
echo "binary refs:       $(printf '%s' "$xml" | grep -c '<Binary ' || true)"
unset xml

echo
echo "==> peak footprint of a full eager parse (db validate)"
# `db validate` runs the complete decrypt + decompress + inner-header +
# XML parse without dumping secrets to stdout. `/usr/bin/time -l` reports
# 'maximum resident set size' and 'peak memory footprint' on stderr.
printf '%s' "$pw" | /usr/bin/time -l "$bin" db validate "$vault" --password-stdin >/dev/null
