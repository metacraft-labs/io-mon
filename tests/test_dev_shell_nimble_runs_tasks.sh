#!/usr/bin/env bash
# The dev shell's `nimble` runs a package task instead of crashing first.
#
# nixpkgs' nimble 0.20.1 links Nix OpenSSL 3, but its TLS setup also looks up
# an SSL method dynamically. Without a pinned `sslVersion`, that lookup is
# unconstrained, and on Darwin it finds the system LibreSSL
# (`/usr/lib/libssl.43.dylib`). nimble then hands LibreSSL's method to OpenSSL
# 3's `SSL_CTX_new_ex` and dies with `SIGSEGV: Illegal storage access` (exit
# 139) before it executes any task, so `nimble test` and every other task in
# this repository fail before a test runs
# (issues/2026-09-28-macos-nimble-test-crashes-before-running-tests.md).
# flake.nix builds the dev shell's nimble with `-d:sslVersion=3`, which binds
# the lookup to the OpenSSL ABI nimble is linked against.
#
# Asserted: in a scratch package outside this repository whose task echoes a
# unique marker, `nimble <task>` run inside `nix develop <this repo>` exits 0
# and prints the marker. `nimble tasks` is not a usable probe: it lists tasks
# without reaching the TLS setup, so it passes with the crashing build too.
# The package lives outside the repository so the dev shell's git-hook setup,
# which only acts inside this repository, plays no part. The crash is
# Darwin-only, but the assertion holds on every host the dev shell supports.
#
# The package's `requires "nim ..."` line is load-bearing. Resolving it makes
# nimble look up the official Nim releases, and that lookup is what creates
# the TLS context; a package without it runs its task even with the crashing
# build, and this test would pass vacuously.
#
# Network: the crash happens while the TLS context is created, before any
# connection, so it reproduces with networking denied (checked on Darwin with
# `sandbox-exec` denying `network*`, and with `--offline`). The passing build
# only needs a package list, so nimble runs against a scratch `--nimbleDir`
# seeded with an empty `packages_official.json`: the test neither reads nor
# writes the user's `~/.nimble`, and nimble does not need the network to pass.
#
#   bash tests/test_dev_shell_nimble_runs_tasks.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

PKG="$SCRATCH/nimbleprobe"
NIMBLE_DIR="$SCRATCH/nimble-dir"
MARKER="IO-MON-NIMBLE-TASK-RAN-$$-$RANDOM"
mkdir -p "$PKG" "$NIMBLE_DIR"
# An empty package list: `requires "nim"` is satisfied by the dev shell's
# compiler, so no package is looked up and nimble has nothing to download.
echo '[]' >"$NIMBLE_DIR/packages_official.json"
cat >"$PKG/nimbleprobe.nimble" <<EOF
version     = "0.1.0"
author      = "io-mon tests"
description = "Scratch package for tests/test_dev_shell_nimble_runs_tasks.sh"
license     = "Apache-2.0"
# Load-bearing: resolving this requirement reaches the TLS setup (see above).
requires "nim >= 2.0.0"

task probe, "Print the marker":
  echo "$MARKER"
EOF

# A command substitution does not abort the script under `set -e`, so the
# status is captured explicitly. stderr is kept: it carries nimble's
# `SIGSEGV: Illegal storage access` line when the crash comes back.
status=0
output="$(cd "$PKG" && nix develop "$REPO" --no-write-lock-file -c nimble --nimbleDir="$NIMBLE_DIR" probe 2>&1)" || status=$?

if [ "$status" -ne 0 ]; then
  reason=""
  if [ "$status" -eq 139 ] || grep -q 'SIGSEGV' <<<"$output"; then
    reason=" (SIGSEGV: the TLS-method mismatch from the issue)"
  fi
  fail "the dev shell's nimble exited $status$reason before running the task; output:
$output"
fi
grep -qF "$MARKER" <<<"$output" \
  || fail "the dev shell's nimble exited 0 but did not run the task; output:
$output"

echo "PASS: the dev shell's nimble runs a package task"
