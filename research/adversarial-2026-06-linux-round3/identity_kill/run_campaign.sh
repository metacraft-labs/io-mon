#!/usr/bin/env bash
set -u

ROOT=/tmp/io_mon_campaign_identity_kill
IOMON=/home/zahary/m/dev/io-mon-hardening-work/build/bin/io-mon
SHIM=/home/zahary/m/dev/io-mon-hardening-work/build/lib/librepro_monitor_shim.so

run_capture() {
  local name=$1
  shift
  local dep="$ROOT/$name.rdep"
  local out="$ROOT/$name.out"
  local inspect="$ROOT/$name.inspect.txt"
  REPRO_MONITOR_SHIM_LIB="$SHIM" "$IOMON" run --depfile "$dep" -- "$@" >"$out" 2>&1
  local code=$?
  "$IOMON" inspect "$dep" --format text >"$inspect" 2>&1
  local inspect_code=$?
  printf '%s run_exit=%s inspect_exit=%s dep=%s inspect=%s\n' "$name" "$code" "$inspect_code" "$dep" "$inspect"
  sed -n '1p' "$inspect"
  grep -F "$ROOT/marker.txt" "$inspect" || true
}

printf 'marker for io-mon adversarial campaign\n' >"$ROOT/marker.txt"

run_capture baseline "$ROOT/baseline_read" "$ROOT/marker.txt"

run_capture kill_after_read "$ROOT/kill_after_read" "$ROOT/marker.txt"

SOCK="$ROOT/daemon.sock"
"$ROOT/socket_daemon" "$SOCK" "$ROOT/marker.txt" >"$ROOT/socket_daemon.out" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 100); do
  if grep -q '^ready$' "$ROOT/socket_daemon.out" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
run_capture socket_breakaway "$ROOT/socket_client" "$SOCK"
wait "$daemon_pid"
printf 'socket_daemon_exit=%s\n' "$?"

