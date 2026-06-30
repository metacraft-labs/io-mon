#!/bin/bash
N=${1:-100}; IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
breaks=0; incomplete=0; complete_present=0
for run in $(seq 1 $N); do
  dep=/tmp/r3_merge/kill_$run.rdep
  $IOMON run --depfile $dep -- /tmp/r3_merge/killtest /tmp/r3_merge >/dev/null 2>&1
  comp=$($IOMON inspect $dep 2>/dev/null | head -1 | grep -o 'mc[A-Za-z]*')
  has=$(grep -q "killmarker.txt" $dep 2>/dev/null && echo yes || echo no)
  if [ "$has" = no ] && [ "$comp" = mcComplete ]; then echo "BREAK run=$run marker-lost+mcComplete"; breaks=$((breaks+1));
  elif [ "$comp" = mcIncomplete ]; then incomplete=$((incomplete+1));
  elif [ "$has" = yes ] && [ "$comp" = mcComplete ]; then complete_present=$((complete_present+1)); fi
  rm -f $dep
done
echo "DONE runs=$N breaks=$breaks mcIncomplete(safe)=$incomplete complete-with-marker(flushed)=$complete_present"
