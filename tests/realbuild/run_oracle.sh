#!/usr/bin/env bash
# Real-build completeness oracle runner — io-mon-Lossless-Event-Capture M3 part 3
# (design spec §4.5(h), the cardinal-sin gate).
#
# Builds the injected shim + the io-mon CLI + the oracle, then runs the oracle
# against the committed known-closure fixtures under a scratch work dir.
#
#   run_oracle.sh [--fast|--full] [workdir]
#
#   --fast  (default in `just test-realbuild-oracle`) — fixtures A (cmake+ninja
#           and cargo) + the class-(a) SET-vs-file transport gate + the D control.
#           A few seconds; suitable to keep in CI.
#   --full  — additionally the differentials B (ninja `-t deps` / cargo dep-info)
#           and C (`strace -f`), plus the SIGKILL-under-load battery D. ~5s.
#
# TOOLCHAIN PROVENANCE. Every tool this gate needs — cc, cmake, ninja, cargo,
# rustc, strace — now comes from io-mon's OWN `flake.nix` devShell, pinned by
# `flake.lock`.
#
# It did not use to, and the previous note here described that as a deliberate
# choice ("It does NOT provide cmake, ninja, cargo, rustc, strace or cc — every
# one of those comes from the AMBIENT environment"). The consequence was that
# the §4.5(h) cardinal-sin gate could not run from ANY shell: measured, `just
# test-realbuild-oracle` exited 2 with "missing required tool(s) ... cmake cargo
# rustc" in io-mon's own devShell and identically in a bare workspace shell. A
# gate nobody can invoke is not a gate. (The note was also already stale: strace
# had been added to the devShell for the loader-closure test.)
#
# ninja in particular was pulled in by this script with `nix shell nixpkgs#ninja`
# — a MUTABLE FLAKE-REGISTRY lookup, resolving against whatever nixpkgs the host
# last synced, in a script whose entire product is reproducible evidence. That is
# the anti-pattern nim-shm-gset's flake was written to eliminate, and it is gone.
#
# The tools stay CHECKED below rather than assumed: a run from a shell that does
# not carry them aborts naming the missing tool, because discovering it later as
# a fixture build exiting non-zero reads as an io-mon capture gap when it is an
# environment one.
set -euo pipefail

MODE=full
WORKDIR=""
for arg in "$@"; do
  case "$arg" in
    --fast) MODE=fast ;;
    --full) MODE=full ;;
    *) WORKDIR="$arg" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKDIR="${WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/io-mon-realbuild-oracle.XXXXXX")}"
HOOKS_SRC="${STACKABLE_HOOKS_SRC:-$REPO_ROOT/../nim-stackable-hooks/src}"

# Fail fast, and by NAME, on a tool this run needs but the environment does not
# have. Discovering it later (as a fixture build exiting non-zero) reads as an
# io-mon finding when it is an environment one.
missing=()
# ninja is in this list now instead of being fetched on the fly: it comes from
# the devShell like everything else, so its absence is an environment error to
# report, not a reason to reach out to the flake registry.
for tool in cc cmake ninja cargo rustc; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "$MODE" = full ]; then
  command -v strace >/dev/null 2>&1 || missing+=("strace")
fi
if [ ${#missing[@]} -gt 0 ]; then
  echo "run_oracle.sh: missing required tool(s):" "${missing[*]}" >&2
  echo "These ARE provided by io-mon's own devShell (flake.nix), pinned by" >&2
  echo "flake.lock — you are not in it. Run:  nix develop <io-mon> -c just test-realbuild-oracle" >&2
  exit 2
fi

echo "== building shim + io-mon CLI + oracle =="
STACKABLE_HOOKS_SRC="$HOOKS_SRC" "$REPO_ROOT/scripts/build_shim.sh" >/dev/null
nim c --hints:off --warnings:off --threads:on \
  --path:"$REPO_ROOT/src" --path:"$HOOKS_SRC" \
  --out:"$REPO_ROOT/build/bin/io-mon" "$REPO_ROOT/cmd/io_mon_snoop.nim" >/dev/null 2>&1
nim c --hints:off --warnings:off --threads:on \
  --path:"$REPO_ROOT/src" --path:"$HOOKS_SRC" \
  --out:"$REPO_ROOT/build/bin/realbuild-oracle" \
  "$REPO_ROOT/tests/realbuild/oracle.nim" >/dev/null 2>&1

echo "== running oracle ($MODE) in $WORKDIR =="
ORACLE="$REPO_ROOT/build/bin/realbuild-oracle"

# No `nix shell nixpkgs#...` here, deliberately: see TOOLCHAIN PROVENANCE above.
# ninja is checked for by name with the rest of the toolchain and comes from the
# devShell, so the oracle runs against the SAME pinned tools every time.
"$ORACLE" "$MODE" "$WORKDIR"
