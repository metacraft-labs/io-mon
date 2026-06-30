#!/bin/bash
set -e
cd /tmp/r3_residual/res4_forge
IO_MON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
export IO_MON_BREAKAWAY_REPORT_DIR=/tmp/r3_residual/res4_forge/reports
export REPRO_MONITOR_SESSION="r3-session-$(uuidgen)"
mkdir -p "$IO_MON_BREAKAWAY_REPORT_DIR"
rm -f "$IO_MON_BREAKAWAY_REPORT_DIR"/*.io-mon-report
echo "session=$REPRO_MONITOR_SESSION"
SOCK=/tmp/r3_residual/res4_forge/d.sock
rm -f /tmp/r3_residual/res4_forge/daemon.ready
pkill -9 -f /tmp/r3_residual/res4_forge/daemon 2>/dev/null || true
sleep 0.3
./daemon "$SOCK" >daemon.log 2>&1 &
DPID=$!
for i in $(seq 1 20); do [ -f daemon.ready ] && break; sleep 0.1; done
cat daemon.log
MARK="R8-FORGE-$(uuidgen)"
echo "$MARK" > REAL_SECRET.txt
echo "real secret marker = $MARK"
echo "=== forger under io-mon ==="
"$IO_MON" run --depfile forge.rdep -- ./forge_client "$SOCK" /tmp/r3_residual/res4_forge/REAL_SECRET.txt 2>/dev/null
echo "=== forged report on disk ==="
cat "$IO_MON_BREAKAWAY_REPORT_DIR"/*.io-mon-report
echo "=== inspect ==="
"$IO_MON" inspect forge.rdep 2>/dev/null | grep -E "completeness="
"$IO_MON" inspect forge.rdep 2>/dev/null | grep -E "^#[0-9]+ " | sed -E 's/ detail=.*//'
echo "REAL_SECRET in depfile: $("$IO_MON" inspect forge.rdep 2>/dev/null | grep -c REAL_SECRET || true)"
echo "DECOY in depfile: $("$IO_MON" inspect forge.rdep 2>/dev/null | grep -c DECOY || true)"
kill -9 $DPID 2>/dev/null || true
