#!/bin/bash
N=${1:-80}; NMARK=24; IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
breaks=0; falseincomplete=0
for run in $(seq 1 $N); do
  dep=/tmp/r3_merge/fork_$run.rdep
  $IOMON run --depfile $dep -- /tmp/r3_merge/forktree /tmp/r3_merge/markers >/dev/null 2>&1
  comp=$($IOMON inspect $dep 2>/dev/null | head -1 | grep -o 'mc[A-Za-z]*')
  missing=""
  for i in $(seq 0 $((NMARK-1))); do grep -q "marker_$i.txt" $dep 2>/dev/null || missing="$missing $i"; done
  if [ -n "$missing" ] && [ "$comp" = "mcComplete" ]; then echo "BREAK run=$run missing:$missing comp=$comp"; breaks=$((breaks+1));
  elif [ -z "$missing" ] && [ "$comp" != "mcComplete" ]; then echo "FALSE-INCOMPLETE run=$run comp=$comp (all markers present)"; falseincomplete=$((falseincomplete+1)); fi
  rm -f $dep
done
echo "DONE runs=$N breaks=$breaks false-incomplete=$falseincomplete"
