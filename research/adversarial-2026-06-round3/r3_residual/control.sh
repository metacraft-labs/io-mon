#!/bin/bash
set -e
cd /tmp/r3_residual/res4_forge
IO_MON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
export IO_MON_BREAKAWAY_REPORT_DIR=/tmp/r3_residual/res4_forge/empty_reports
mkdir -p "$IO_MON_BREAKAWAY_REPORT_DIR"; rm -f "$IO_MON_BREAKAWAY_REPORT_DIR"/*
SOCK=/tmp/r3_residual/res4_forge/dc.sock
rm -f daemon.ready
pkill -9 -f /tmp/r3_residual/res4_forge/daemon 2>/dev/null || true; sleep 0.3
./daemon "$SOCK" >/dev/null 2>&1 &
DPID=$!
for i in $(seq 1 20); do [ -f daemon.ready ] && break; sleep 0.1; done
echo "ctl-secret" > REAL_SECRET.txt
# use a plain (non-forging) client behaviour: connect but DON'T write a report
"$IO_MON" run --depfile ctl.rdep -- ./forge_client "$SOCK" /tmp/r3_residual/res4_forge/REAL_SECRET.txt 2>/dev/null >/dev/null
# the forger DID write into res4_forge/reports (its own hardcoded? no, it uses env) -> here env points to empty_reports, but forger reads same env -> writes there.
echo "report dir contents: $(ls "$IO_MON_BREAKAWAY_REPORT_DIR")"
echo "completeness WITH forged report present in empty_reports:"
"$IO_MON" inspect ctl.rdep 2>/dev/null | grep -E "completeness="
kill -9 $DPID 2>/dev/null || true
