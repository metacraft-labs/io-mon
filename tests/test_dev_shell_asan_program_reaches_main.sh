#!/usr/bin/env bash
# A program built by the dev shell's compiler with ASan + UBSan reaches main.
#
# On macOS 26 the ASan runtime of nixpkgs' compiler-rt 21.1.8 never finishes
# initialising: `InitializeShadowMemory` asks `get_dyld_hdr` for dyld's header,
# which walks the shared cache with `dyld_shared_cache_iterate_text`; that
# copies a block (`_Block_copy` -> `malloc`), the malloc is ASan's own, and it
# re-enters `AsanInitFromRtl`, which spins forever on the init mutex it already
# holds. Every instrumented program, `puts` and `return 0` included, burns one
# CPU before main, so `scripts/run_sanitizer_tests.sh` never runs a test
# (metacraft-pm issues/2026-10-01-nix-compiler-rt-asan-startup-hangs-on-macos-26.md).
# flake.nix gives the Darwin dev shell a compiler-rt carrying the upstream fix
# (LLVM 2e7d07a33725, "Adopt _dyld_get_dyld_header").
#
# Asserted, for both `cc` and `clang` inside `nix develop <this repo>`: a C
# program compiled with `-fsanitize=address,undefined -g` prints a marker from
# main and exits 0 within a bounded time. A timeout is a FAILURE naming the
# hang, never a skip. As the positive control, the same compiler's heap
# overflow probe must be reported by ASan: a build whose sanitizer flags were
# silently dropped would reach main too, and would pass vacuously.
# The hang is Darwin-only, but the assertion holds on every host the dev shell
# supports.
#
#   bash tests/test_dev_shell_asan_program_reaches_main.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# Measured on the hanging runtime: still spinning after ten minutes. A healthy
# start takes well under a second, so the bound only has to absorb a loaded
# host.
TIMEOUT_S="${IO_MON_ASAN_STARTUP_TIMEOUT_S:-30}"
MARKER="IO-MON-ASAN-REACHED-MAIN-$$-$RANDOM"

cat >"$SCRATCH/reaches_main.c" <<EOF
#include <stdio.h>
int main(void) { puts("$MARKER"); return 0; }
EOF
cat >"$SCRATCH/overflow.c" <<'EOF'
#include <stdlib.h>
int main(void) {
  volatile char *p = malloc(4);
  p[4] = 1;
  return 0;
}
EOF

# Runs inside the dev shell. Exit codes: 0 pass; 10 compile failed; 124 the
# program timed out (the hang); 20 the program ran but missed the marker or
# failed; 30 the control overflow was not reported.
cat >"$SCRATCH/probe.sh" <<'EOF'
set -uo pipefail
scratch="$1" marker="$2" timeout_s="$3"
export ASAN_OPTIONS="detect_leaks=0"
for compiler in cc clang; do
  echo "--- $compiler = $(command -v "$compiler")"
  "$compiler" -fsanitize=address,undefined -g -o "$scratch/reaches_main_$compiler" "$scratch/reaches_main.c" || exit 10
  if command -v otool >/dev/null; then
    otool -L "$scratch/reaches_main_$compiler" | grep -i asan || true
  fi
  out="$(timeout -k 5 "$timeout_s" "$scratch/reaches_main_$compiler" 2>&1)"
  rc=$?
  printf '%s\n' "$out"
  [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] && exit 124
  [ "$rc" -eq 0 ] && grep -qF "$marker" <<<"$out" || exit 20

  "$compiler" -fsanitize=address,undefined -g -o "$scratch/overflow_$compiler" "$scratch/overflow.c" || exit 10
  out="$(timeout -k 5 "$timeout_s" "$scratch/overflow_$compiler" 2>&1)"
  rc=$?
  [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] && exit 124
  if [ "$rc" -eq 0 ] || ! grep -q 'heap-buffer-overflow' <<<"$out"; then
    printf '%s\n' "$out"
    exit 30
  fi
  echo "--- $compiler: control overflow reported by ASan (exit $rc)"
done
exit 0
EOF

# The scratch directory is outside this repository, so the dev shell's
# git-hook setup plays no part. Clear the ambient environment so a host
# compiler on PATH (or compiler flags) cannot hide a missing shell prerequisite.
status=0
output="$(cd "$SCRATCH" && nix develop "$REPO" --ignore-environment --no-write-lock-file -c bash "$SCRATCH/probe.sh" "$SCRATCH" "$MARKER" "$TIMEOUT_S" 2>&1)" || status=$?

case "$status" in
  0) ;;
  124)
    fail "an ASan+UBSan program built by the dev shell's compiler did not reach main within ${TIMEOUT_S}s: the compiler-rt ASan startup hang (AsanInitInternal -> get_dyld_hdr -> malloc -> AsanInitFromRtl self-deadlock on macOS 26; see flake.nix); output:
$output" ;;
  10) fail "the dev shell's compiler could not build an ASan+UBSan program; output:
$output" ;;
  20) fail "an ASan+UBSan program built by the dev shell's compiler did not print its marker and exit 0; output:
$output" ;;
  30) fail "control: ASan did not report a heap overflow, so the sanitizer is not active and the start-up check would be vacuous; output:
$output" ;;
  *) fail "the dev shell did not start or the probe exited $status; output:
$output" ;;
esac
grep -qF "$MARKER" <<<"$output" || fail "the probe passed without printing the marker; output:
$output"

# The compilers and the ASan runtime they linked, for the log.
grep -E '^--- |asan' <<<"$output" || true
echo "PASS: ASan+UBSan programs built by the dev shell's cc and clang reach main, and ASan reports the control overflow"
