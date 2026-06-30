#!/usr/bin/env bash
set -euo pipefail

scratch="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${IO_MON_TARGET:-/home/zahary/m/dev/io-mon-hardening-work}"
io_mon="${IO_MON_BIN:-$target/build/bin/io-mon}"
shim="${IO_MON_SHIM:-$target/build/lib/librepro_monitor_shim.so}"

cc="${CC:-cc}"
mkdir -p "$scratch/bin" "$scratch/out" "$scratch/markers"

printf 'MARKER baseline %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$scratch/markers/baseline.txt"
printf 'MARKER baseline-open %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$scratch/markers/baseline_open.txt"
printf 'MARKER raw-openat %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$scratch/markers/raw_openat.txt"
printf 'MARKER raw-openat2 %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$scratch/markers/raw_openat2.txt"
printf 'MARKER raw-statx %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$scratch/markers/raw_statx.txt"
printf 'MARKER io-uring %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$scratch/markers/io_uring.txt"

"$cc" -Wall -Wextra -O2 -o "$scratch/bin/baseline_fopen" "$scratch/baseline_fopen.c"
"$cc" -Wall -Wextra -O2 -o "$scratch/bin/baseline_open_read" "$scratch/baseline_open_read.c"
"$cc" -Wall -Wextra -O2 -o "$scratch/bin/raw_openat_read" "$scratch/raw_openat_read.c"
"$cc" -Wall -Wextra -O2 -o "$scratch/bin/raw_openat2_read" "$scratch/raw_openat2_read.c"
"$cc" -Wall -Wextra -O2 -o "$scratch/bin/raw_statx_probe" "$scratch/raw_statx_probe.c"
if "$cc" -Wall -Wextra -O2 -o "$scratch/bin/io_uring_probe" "$scratch/io_uring_probe.c" -luring 2>"$scratch/out/io_uring_build.err"; then
  have_io_uring=1
else
  have_io_uring=0
fi

run_plain() {
  local name="$1" marker="$2"
  "$scratch/bin/$name" "$marker" > "$scratch/out/$name.plain.out" 2> "$scratch/out/$name.plain.err" || true
}

run_monitored() {
  local name="$1" marker="$2"
  local dep="$scratch/out/$name.rdep"
  local inspect="$scratch/out/$name.inspect.txt"
  "$io_mon" run --depfile "$dep" -- "$scratch/bin/$name" "$marker" \
    > "$scratch/out/$name.mon.out" 2> "$scratch/out/$name.mon.err" || true
  "$io_mon" inspect "$dep" > "$inspect" 2> "$scratch/out/$name.inspect.err" || true
}

classify() {
  local name="$1" marker="$2"
  local inspect="$scratch/out/$name.inspect.txt"
  local marker_absent=0 complete=0 incomplete=0
  if ! grep -F -- "$marker" "$inspect" >/dev/null 2>&1; then marker_absent=1; fi
  if grep -E 'completeness[ =:]mcComplete|mcComplete' "$inspect" >/dev/null 2>&1; then complete=1; fi
  if grep -E 'completeness[ =:]mcIncomplete|mcIncomplete' "$inspect" >/dev/null 2>&1; then incomplete=1; fi

  if [[ "$marker_absent" -eq 1 && "$complete" -eq 1 && "$incomplete" -eq 0 ]]; then
    echo "CONFIRMED_BREAK $name marker_absent completeness=mcComplete marker=$marker"
  elif [[ "$incomplete" -eq 1 ]]; then
    echo "CAUGHT_OR_BLOCKED $name completeness=mcIncomplete marker=$marker"
  elif [[ "$marker_absent" -eq 0 ]]; then
    echo "CAUGHT_OR_RECORDED $name marker_present marker=$marker"
  else
    echo "INCONCLUSIVE $name marker_absent completeness_not_mcComplete marker=$marker"
  fi
}

run_plain baseline_fopen "$scratch/markers/baseline.txt"
run_plain baseline_open_read "$scratch/markers/baseline_open.txt"
run_plain raw_openat_read "$scratch/markers/raw_openat.txt"
run_plain raw_openat2_read "$scratch/markers/raw_openat2.txt"
run_plain raw_statx_probe "$scratch/markers/raw_statx.txt"
if [[ "$have_io_uring" -eq 1 ]]; then
  run_plain io_uring_probe "$scratch/markers/io_uring.txt"
fi

if [[ ! -x "$io_mon" || ! -f "$shim" ]]; then
  {
    echo "HARNESS_UNAVAILABLE"
    echo "io_mon=$io_mon"
    echo "shim=$shim"
    echo "plain probe outputs are under $scratch/out"
    echo "rerun after the main agent builds the harness:"
    echo "  $scratch/run_campaign.sh"
  } | tee "$scratch/out/summary.txt"
  exit 0
fi

run_monitored baseline_fopen "$scratch/markers/baseline.txt"
run_monitored baseline_open_read "$scratch/markers/baseline_open.txt"
run_monitored raw_openat_read "$scratch/markers/raw_openat.txt"
run_monitored raw_openat2_read "$scratch/markers/raw_openat2.txt"
run_monitored raw_statx_probe "$scratch/markers/raw_statx.txt"
if [[ "$have_io_uring" -eq 1 ]]; then
  run_monitored io_uring_probe "$scratch/markers/io_uring.txt"
fi

{
  echo "SUMMARY"
  baseline_status="$(classify baseline_open_read "$scratch/markers/baseline_open.txt")"
  echo "$baseline_status"
  classify baseline_fopen "$scratch/markers/baseline.txt"
  if [[ "$baseline_status" != CAUGHT_OR_RECORDED* ]]; then
    echo "HARNESS_SMOKE_FAILED explicit libc open/read marker was not recorded; raw probes are INCONCLUSIVE"
    echo "INCONCLUSIVE raw_openat_read smoke_failed marker=$scratch/markers/raw_openat.txt"
    echo "INCONCLUSIVE raw_openat2_read smoke_failed marker=$scratch/markers/raw_openat2.txt"
    echo "INCONCLUSIVE raw_statx_probe smoke_failed marker=$scratch/markers/raw_statx.txt"
  else
    classify raw_openat_read "$scratch/markers/raw_openat.txt"
    classify raw_openat2_read "$scratch/markers/raw_openat2.txt"
    classify raw_statx_probe "$scratch/markers/raw_statx.txt"
  fi
  if [[ "$have_io_uring" -eq 1 ]]; then
    classify io_uring_probe "$scratch/markers/io_uring.txt"
  else
    echo "SKIPPED io_uring_probe liburing unavailable; build log=$scratch/out/io_uring_build.err"
  fi
} | tee "$scratch/out/summary.txt"
