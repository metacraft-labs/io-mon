#!/bin/bash
# Run the concurrency stress N times; for each run verify all 32 markers present + completeness.
N=${1:-200}
NTHREADS=32
IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
breaks=0
incomplete=0
for run in $(seq 1 $N); do
  dep=/tmp/r3_merge/conc_$run.rdep
  $IOMON run --depfile $dep -- /tmp/r3_merge/conc /tmp/r3_merge/markers >/dev/null 2>&1
  comp=$($IOMON inspect $dep 2>/dev/null | head -1 | grep -o 'completeness=mc[A-Za-z]*')
  # count distinct markers seen in file-read records
  missing=""
  for i in $(seq 0 $((NTHREADS-1))); do
    if ! grep -q "marker_$i.txt" $dep 2>/dev/null; then
      missing="$missing $i"
    fi
  done
  if [ -n "$missing" ]; then
    if [ "$comp" = "completeness=mcComplete" ]; then
      echo "BREAK run=$run missing:$missing comp=$comp"
      breaks=$((breaks+1))
    else
      # missing but flagged incomplete = fail-closed (acceptable), but still note
      echo "missing-but-incomplete run=$run missing:$missing comp=$comp"
      incomplete=$((incomplete+1))
    fi
  fi
  rm -f $dep
done
echo "DONE runs=$N breaks=$breaks missing-but-incomplete=$incomplete"
