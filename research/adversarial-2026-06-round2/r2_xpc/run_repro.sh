#!/bin/bash
# Self-contained repro: raw Mach-IPC breakaway false negative against io-mon.
# Builds a Mach RPC server (started OUTSIDE io-mon) + client (run UNDER io-mon).
# The server reads a unique marker on the client's behalf; io-mon never sees it.
set -e
cd /tmp/r2_xpc
IO_MON=/Users/zahary/m/dev/io-mon/build/bin/io-mon

/usr/bin/clang -o mach_server mach_server.c 2>/dev/null
/usr/bin/clang -o mach_client mach_client.c 2>/dev/null

pkill -9 -f /tmp/r2_xpc/mach_server 2>/dev/null || true
sleep 0.5
SVC="com.example.r2xpc.$(date +%s).$$"
./mach_server "$SVC" >/tmp/r2_xpc/mserver.log 2>&1 &
SRV=$!
sleep 1

MARK="MACH-FNEG-$(uuidgen)"
echo "$MARK" > /tmp/r2_xpc/secret-2.txt
echo "marker = $MARK"
echo "out-of-tree server pid = $SRV (NOT under io-mon)"
echo
echo "### client output (under io-mon) — folds the marker it got over Mach IPC:"
"$IO_MON" run --depfile /tmp/r2_xpc/mach.rdep -- \
    /tmp/r2_xpc/mach_client /tmp/r2_xpc/secret-2.txt "$SVC"
echo
echo "### server proof it read the marker:"
grep secret-2 /tmp/r2_xpc/mserver.log
echo
echo "### io-mon inspect — marker ABSENT, completeness mcComplete:"
"$IO_MON" inspect /tmp/r2_xpc/mach.rdep
echo
echo "secret-2 occurrences in depfile: $("$IO_MON" inspect /tmp/r2_xpc/mach.rdep --format jsonl | grep -c secret-2)"

kill -9 $SRV 2>/dev/null || true
