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
# ninja is NOT in io-mon's dev shell, so this script obtains it via
# `nix shell nixpkgs#ninja`. cmake / cargo / rustc / strace / cc come from the
# dev shell (or the ambient environment when already inside one).
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

if command -v ninja >/dev/null 2>&1; then
  "$ORACLE" "$MODE" "$WORKDIR"
else
  # Pull ninja in without disturbing the rest of the toolchain on PATH.
  nix shell nixpkgs#ninja --command "$ORACLE" "$MODE" "$WORKDIR"
fi
