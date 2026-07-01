#!/bin/bash
# run.sh <probe-binary> <marker-file-or-dir> [extra-arg]
IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
name=$(basename "$1")
dep=/tmp/r5_unhooked/${name}.rdep
"$IOMON" run --depfile "$dep" -- "$@" 2>/dev/null
echo "----- inspect $name -----"
"$IOMON" inspect "$dep" | grep -E 'completeness=|file-read|file-open|path-probe|dir|event-loss|external|non-determ|getattr' 
echo "COMPLETENESS: $("$IOMON" inspect "$dep" | head -1)"
