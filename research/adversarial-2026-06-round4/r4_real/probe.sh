#!/usr/bin/env bash
# probe.sh NAME -- cmd args...   : run under io-mon, print completeness + downgrade reasons + read count
export CT_SANDBOX_TOOLS_DIR=/Users/zahary/m/dev/reprobuild/recipes/sandbox-tools/bundle
IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
name="$1"; shift; [ "$1" = "--" ] && shift
rdep="/tmp/r4_real/${name}.rdep"
$IOMON run --depfile "$rdep" -- "$@" >/tmp/r4_real/${name}.out 2>/tmp/r4_real/${name}.err
ec=$?
if [ ! -f "$rdep" ]; then echo "[$name] NO RDEP (exit=$ec)"; tail -2 /tmp/r4_real/${name}.err; return 2>/dev/null; exit 0; fi
line1=$($IOMON inspect "$rdep" 2>/dev/null | head -1)
nreads=$($IOMON inspect "$rdep" 2>/dev/null | grep -c 'file-read\|mrFileRead')
nproc=$(echo "$line1" | grep -oE 'records=[0-9]+')
echo "[$name] exit=$ec  $line1  reads=$nreads"
$IOMON inspect "$rdep" 2>/dev/null | grep -iE 'event-loss' | sed 's/detail=/=> /' | sed -E 's/#[0-9]+ event-loss pid=0 tid=0 //' | sort | uniq -c
