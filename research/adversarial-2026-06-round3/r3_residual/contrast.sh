#!/bin/bash
set -e
cd /tmp/r3_residual/res4_forge
IO_MON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
cp /Users/zahary/m/dev/io-mon/research/adversarial-2026-06-round2/r2_machinery/malicious_client.c .
/usr/bin/clang -o malicious_client malicious_client.c 2>/dev/null
export IO_MON_BREAKAWAY_REPORT_DIR=/tmp/r3_residual/res4_forge/reports2
mkdir -p "$IO_MON_BREAKAWAY_REPORT_DIR"; rm -f "$IO_MON_BREAKAWAY_REPORT_DIR"/*
SOCK=/tmp/r3_residual/res4_forge/dx.sock
rm -f daemon.ready
pkill -9 -f /tmp/r3_residual/res4_forge/daemon 2>/dev/null || true; sleep 0.3
./daemon "$SOCK" >/dev/null 2>&1 &
DPID=$!
for i in $(seq 1 20); do [ -f daemon.ready ] && break; sleep 0.1; done
echo "secret" > REAL_SECRET.txt
echo "=== OLD forgery (no run/no complete/no reads) -> should be REJECTED ==="
"$IO_MON" run --depfile old.rdep -- ./malicious_client "$SOCK" /tmp/r3_residual/res4_forge/REAL_SECRET.txt 2>/dev/null >/dev/null || true
echo "report written:"; cat "$IO_MON_BREAKAWAY_REPORT_DIR"/*.io-mon-report 2>/dev/null
"$IO_MON" inspect old.rdep 2>/dev/null | grep -E "completeness="
kill -9 $DPID 2>/dev/null || true
