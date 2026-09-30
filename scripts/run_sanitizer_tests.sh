#!/usr/bin/env bash
#
# Compile and run a test tier under AddressSanitizer + UndefinedBehaviorSanitizer.
#
# THE GATING RESULT, so the numbers below have an anchor: on an unmutated tree at
# io-mon `53994c0` this script is rc=0, 25 files, 0 failed, with no ASan report
# and no UBSan `runtime error:` anywhere in the sweep -- 320 s and 435 s on two
# runs on a dedicated GitHub-hosted `ubuntu-24.04` runner, against 5104 s on a
# 32-core workstation that was
# running four such sweeps at once at load 108-293.  Quote the first figure: the
# gap between them is contention, not instrumentation.  Everything else quoted in
# this header was measured on a deliberately broken tree, and none of it would
# mean anything without that line -- a check that is red on everything grades
# nothing.
#
# WHY THIS EXISTS.  io-mon's codec copies string bodies and fixed-width header
# fields with `copyMem`.  A wrong SIZE on one of those copies is invisible to
# every oracle the suite has: the bytes that land inside the buffer are still
# correct, so a round-trip check, a byte-for-byte golden and a field digest all
# agree with themselves while the copy runs past the end of its allocation.
# Measured at io-mon `53994c0`: growing `writeString`'s copy length by one byte
# leaves the ENTIRE portable tier green -- 25 files, including both wire-format
# files -- because the byte written past the region is the string's NUL
# terminator, so the logical contents are unchanged and there is no wrong output
# for anything to compare.  Under this script the same mutant reddens 11 of the
# 25 files, every one an ASan `heap-buffer-overflow WRITE ... 0 bytes after` the
# region in `writeString`, called from `encodeFrame`.  This script is what makes
# that check run without a reviewer choosing to run it.
#
# No byte count is quoted on purpose.  The write size and the region size are
# whatever string that particular test happened to encode, so they differ from
# file to file -- 18/97, 20/118, 33/144, 41/120 and 551/653 all occur in the same
# sweep.  A pair lifted out of one log reads as a signature of the defect and is
# not one; the stable part is the access kind, the ZERO offset past the region,
# and the frame.
#
# AND ITS VALUE IS NOT UNIFORM ACROSS DEFECTS -- do not let this section be read
# as "the sanitizers catch the codec's memory bugs".  Two other mutations of the
# same file were measured at the same commit, and the ordinary tier already
# handles both:
#
#   * `readString`'s bounds check REMOVED -- the tier already goes red, but only
#     by dying (SIGBUS, exit 135) with no verdict printed.  This script turns
#     that into a named diagnosis (`heap-buffer-overflow READ of size 65540` at
#     `readString`).  An upgrade in DIAGNOSIS, not in detection.
#   * `readString`'s bound off by one -- `test_io_mon_wire_negative_oracle`'s
#     `detaillen_one_byte_past_the_payload` case already fails BY VERDICT.  THIS
#     SCRIPT ADDS NOTHING THERE.
#
# So the `writeString` sizing mutant above is the whole of what this script buys
# that the tree did not already have.
#
# `-d:useMalloc` IS LOAD-BEARING AND IS PASSED EXPLICITLY.  Nim's default
# allocator carves per-thread regions out of `mmap`, so every Nim heap object
# lives inside one big mapping that ASan knows nothing about: a write one byte
# past a `seq` lands in the same mapping and is reported as nothing at all.
# With `-d:useMalloc` each object is its own `malloc` block with ASan redzones
# around it, which is the only configuration in which this arm grades anything.
#
# THAT IS MEASURED, NOT ASSERTED.  The same mutant swept with everything below
# unchanged except this one flag removed: 25 files, 0 failed, and ZERO ASan
# reports in any of the 25 logs -- against 11 failed with the flag.  The
# uninstrumented-looking result is not a missing sanitizer: those binaries do
# link libasan (31 `__asan` and 16 `__ubsan` symbols in each).  ASan is present
# and simply cannot see an overflow that stays inside Nim's big mapping.  Remove
# this flag and the job still passes, still looks instrumented, and grades
# nothing -- which is exactly why it is on the command line where a reader of
# this file can see it.
#
# AND IT IS PASSED HERE RATHER THAN INHERITED.  The same flag has an
# `{.error.}` guard in the three shim entry modules (`src/io_mon/shim/*`),
# which refuse to compile as `--app:lib` without it.  The guard is correct and
# is left alone -- the shim is loaded into processes whose threads it does not
# own, and Nim's per-thread heaps cannot survive that (see
# `docs/contributors/shim-build-policy.md`).  What the guard punishes is
# ASSUMING the flag travels: a `nim c` a test spawns for itself is a fresh
# compiler invocation that inherits nothing from this script's command line, so
# every such compile must carry its own `-d:useMalloc`.  Putting the flag in
# `config.nims` to "fix" that would silently change the allocator for every
# build in the checkout, which is a product change wearing a CI change's
# clothes.  So: explicit on the command line, nowhere else.
#
# WHAT THIS ARM DOES NOT COVER, AND WHY THAT IS NOT A GAP IT HIDES.  Only the
# Nim modules compiled by THIS script are instrumented:
#
#   * The live-monitor tiers -- `tests/posix`, `tests/linux`, `tests/macos`,
#     `tests/windows` -- are NOT swept.  Grading them would mean injecting an
#     ASan-instrumented shim into arbitrary host processes, which is a different
#     problem from grading the codec and has its own open question (see
#     `issues/2026-09-30-linux-shim-runtime-settings-diverge-from-policy.md`).
#   * The shim shared library is not built here at all.
#   * 8 of the 25 portable tests drive a `nim` of their own -- the CLI smoke
#     build, the handle-exclusivity negative compiles, the nimcache-layout probe,
#     the cross-target `nim check`s, the child-env cases and the signal-handler
#     policy check.  Those children are ordinary uninstrumented builds and stay
#     that way: a spawned `nim c` inherits nothing from this command line.  So
#     this script PAYS for roughly a third of the tier's compiler work without
#     GRADING it.
#   * Leak detection is off (`detect_leaks=0`, and see the export below).  This
#     grades memory SAFETY, not retention.
#
# The tier actually swept is printed, file by file, at the top of every run, so
# the arm's coverage is readable from its log rather than inferred from its
# name.  Nothing here is sampled: every `test_*.nim` in the named directories is
# compiled and run.
#
# TWO KNOWN-BAD TESTS ARE NOT IN THE DEFAULT TIER, and that is checked rather
# than hoped: `test_io_mon_allocator_clock_reentrancy` (needs `rustc`, absent
# from a plain shell) and `test_io_mon_shim_fd_path_concurrency` (hangs before
# any case reports) both live in `tests/linux/`, which this arm does not sweep.
# No file in `tests/portable/` requires `rustc`.  If a future caller points this
# script at `tests/linux`, those two are its problem to deal with deliberately
# -- this script has no skip list and will not invent one silently.
#
# WHAT UBSAN IS HERE FOR, given that it is not what catches the codec's copy
# bugs.  Every out-of-bounds `copyMem` in the codec is an ASAN finding, and UBSan
# reports nothing at all on a clean tree.  A sanitizer that has never fired can
# only be justified by what it WOULD catch, so that was measured too.  Two
# one-line probes to `codec.nim`, run under this script:
#
#   * `readU32Le`'s shift amount widened  -> `runtime error: shift exponent 64 is
#     too large for 64-bit type`.
#   * `loadU32Le`'s `copyMem` replaced by a reinterpreting pointer cast, which is
#     the obvious "faster" rewrite of it  -> `runtime error: load of misaligned
#     address ... which requires 4 byte alignment`.
#
# ASan is silent on both.  Both are one edit away from the code as written, which
# is what earns UBSan its place next to a near-zero marginal cost: same compile,
# same run, and ASan dominates both.  Read its silence as "no such defect today",
# not as coverage of the copy sizes.  Those are ASan's.
#
# TWO LIMBS OF AN EARLIER RATIONALE WERE WRONG; they are recorded so they are not
# re-added.  The big-endian shift arms of the fixed-offset accessors sit in a
# `when cpuEndian == littleEndian: ... else:` and are not compiled on this arm's
# platform at all.  And the out-of-range enum conversions are in `encode.nim` and
# `shm/dep_queue.nim`, not `codec.nim`, where `decodeRecordPayload` range-checks
# `kindOrd`, `obsOrd` and `probeOrd` before converting each one -- so there is no
# unguarded conversion for UBSan to reach, and Nim's own range check would fire
# first if there were.
#
# USAGE
#   scripts/run_sanitizer_tests.sh [<test-dir> ...]      # default: tests/portable
#
# Exit status is 0 only if every file compiled and ran clean.  A failing file
# does not stop the sweep, and each file's status is written to its own
# `.rc` file next to its log -- never read back out of a pipeline, whose exit
# status is its last stage's and not the compiler's.

# NOT `set -e`: the whole point is to keep going after a red file.
set -uo pipefail

# Deterministic file order on every host: the tier is swept in C collation, and
# the sweep order is part of what a run's log means.
export LC_COLLATE=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root" || exit 1

dirs=("$@")
if [ "${#dirs[@]}" -eq 0 ]; then
  dirs=("tests/portable")
fi

out_dir="${IO_MON_SANITIZER_OUT:-$repo_root/build/sanitizers}"
# Clear only the subdirectories this script owns, never `$out_dir` itself: the
# path is overridable and an `rm -rf` of a caller-supplied directory is a
# different kind of program from a test runner.
rm -rf "${out_dir:?}/bin" "${out_dir:?}/logs" "${out_dir:?}/nimcache"
mkdir -p "$out_dir/bin" "$out_dir/logs" "$out_dir/nimcache" "$out_dir/xdg-cache" || exit 1

# A private XDG_CACHE_HOME so a concurrent ordinary build in this checkout and
# this sanitizer build cannot reach into each other's Nim caches, and an
# explicit per-file --nimcache below for the same reason at object-file level
# (Nim keys its default cache on the project NAME only -- see config.nims).
export XDG_CACHE_HOME="$out_dir/xdg-cache"

# `detect_leaks=0`: this arm grades memory SAFETY, not retention.  Nim's
# runtime keeps process-global state alive to exit by design (thread-local
# registries, interned literals), so leak checking here reports the runtime's
# architecture rather than a defect, on every file, and would make the arm red
# on an unmutated tree -- an arm that is red on everything grades nothing.
# `exitcode=1` is the default and is stated anyway, because the job's verdict
# is this exit status.
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=1:print_stacktrace=1:strict_string_checks=1:detect_stack_use_after_return=1${ASAN_OPTIONS:+:$ASAN_OPTIONS}"
# UBSan RECOVERS by default: it prints the diagnosis and carries on, and the
# process still exits 0.  `halt_on_error=1` plus `-fno-sanitize-recover` below
# is what turns a diagnosis into a verdict.
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1${UBSAN_OPTIONS:+:$UBSAN_OPTIONS}"

nim_flags=(
  --hints:off
  --path:"${STACKABLE_HOOKS_SRC:-../nim-stackable-hooks/src}"
  --path:tests/helpers
  --debugger:native            # ASan reports need line numbers to be readable.
  -d:useMalloc                 # see the header -- without this the arm is blind.
  "--passC:-fsanitize=address,undefined"
  "--passC:-fno-omit-frame-pointer"
  "--passC:-fno-sanitize-recover=undefined"
  "--passL:-fsanitize=address,undefined"
)

# Collect the tier first, so the run announces what it is about to grade.
# A glob, not `ls`: the shell expands it already sorted (LC_COLLATE=C above, so
# the order is the same on every host) and handles names `ls` output would
# mangle. `nullglob` so a tier with no test files contributes nothing rather
# than a literal unexpanded pattern.
files=()
shopt -s nullglob
for dir in "${dirs[@]}"; do
  [ -d "$dir" ] || continue
  for f in "$dir"/test_*.nim; do
    files+=("$f")
  done
done
shopt -u nullglob

echo "=== io-mon sanitizer arm (AddressSanitizer + UndefinedBehaviorSanitizer)"
echo "--- tiers swept: ${dirs[*]}"
echo "--- files swept: ${#files[@]}"
for f in "${files[@]}"; do
  echo "      $f"
done
echo "--- nim flags: ${nim_flags[*]}"
echo "--- ASAN_OPTIONS=$ASAN_OPTIONS"
echo "--- UBSAN_OPTIONS=$UBSAN_OPTIONS"
echo "--- every test_*.nim in those directories is compiled and run; nothing is"
echo "    sampled, and there is no skip list."
echo "--- NOT COVERED by this job, so do not read a green tick as more than it is:"
echo "      * the live-monitor tiers: tests/posix, tests/linux, tests/macos,"
echo "        tests/windows -- none of them are swept here"
echo "      * the shim shared library -- not built by this arm at all"
echo "      * any compiler or binary a test spawns for itself (those children are"
echo "        ordinary uninstrumented builds -- 8 of the 25 portable tests do this)"
echo "      * leaks: detect_leaks=0, this grades memory SAFETY not retention"
echo "--- ASan is what grades the codec's copy sizes. UBSan grades a different"
echo "    class -- measured: a widened shift exponent and a misaligned scalar"
echo "    load, both of which ASan is silent on -- and has never reported one of"
echo "    the copy-size defects; its silence is not coverage of them."
echo

if [ "${#files[@]}" -eq 0 ]; then
  echo "=== no test files found in: ${dirs[*]}" >&2
  exit 1
fi

failed=()
started_at=$SECONDS

for f in "${files[@]}"; do
  stem="$(basename "$f" .nim)"
  log="$out_dir/logs/$stem.log"
  rc_file="$out_dir/logs/$stem.rc"

  echo "=== $f"
  # Builds are SERIALISED on purpose: an ASan build is slower and heavier than
  # an ordinary one, and this repo's hosts are routinely loaded well past their
  # core count.
  nim c -r \
    "${nim_flags[@]}" \
    --nimcache:"$out_dir/nimcache/$stem" \
    --out:"$out_dir/bin/$stem" \
    "$f" >"$log" 2>&1
  # Capture the COMPILER's status directly, and persist it to a file.  A
  # `nim c -r ... | tee` would report tee's status instead, which is how a
  # green report survives a red build.
  rc=$?
  printf '%s\n' "$rc" >"$rc_file"

  if [ "$rc" -ne 0 ]; then
    failed+=("$stem (exit $rc)")
    echo "--- FAILED: $stem (exit $rc)"
    # Sanitizer reports are the reason this arm exists; surface them in the job
    # log rather than only in an uploaded artifact.
    grep -n -m 40 -E 'ERROR: (Address|Leak)Sanitizer|runtime error:|SUMMARY: (Address|Undefined)' "$log" || true
    tail -n 40 "$log"
  else
    echo "--- ok: $stem"
  fi
done

elapsed=$((SECONDS - started_at))
echo
echo "=== sanitizer arm finished in ${elapsed}s: ${#files[@]} files, ${#failed[@]} failed"
if [ "${#failed[@]}" -ne 0 ]; then
  for entry in "${failed[@]}"; do
    echo "    FAILED: $entry"
  done
  exit 1
fi
exit 0
