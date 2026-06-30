#!/bin/bash
# race2.sh <label> <mode> <K> <N>   (uses child2: marker mode K junk)
LABEL="$1"; MODE="$2"; K="$3"; N="${4:-80}"
IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
cap=0; BREAK=0; held_dg=0; brk_ps=0
for i in $(seq 1 $N); do
  MARK="/tmp/r4_proc/rm_${LABEL}_${i}.txt"; echo "TK_${LABEL}_${i}_$RANDOM" > "$MARK"
  DEP="/tmp/r4_proc/rd_${LABEL}_${i}.rdep"
  $IOMON run --depfile "$DEP" -- /tmp/r4_proc/child2 "$MARK" "$MODE" "$K" /tmp/r4_proc/junk.txt >/dev/null 2>&1
  OUT=$($IOMON inspect "$DEP" 2>/dev/null)
  mread=$(echo "$OUT"|grep -c "file-read.*$(basename $MARK)")
  comp=$(echo "$OUT"|grep -o 'completeness=[a-zA-Z]*'|head -1)
  psc=$(echo "$OUT"|grep -c 'process-start')
  if [ "$mread" -ge 1 ]; then cap=$((cap+1))
  elif [ "$comp" = "completeness=mcComplete" ]; then
    BREAK=$((BREAK+1)); [ "$psc" -ge 1 ] && brk_ps=$((brk_ps+1))
    cp "$DEP" "/tmp/r4_proc/BREAK_${LABEL}_${i}.rdep" 2>/dev/null
  else held_dg=$((held_dg+1)); fi
  rm -f "$MARK" "$DEP"
done
echo "[$LABEL mode=$MODE K=$K N=$N] captured=$cap  BREAK(lost+mcComplete)=$BREAK(ps_durable=$brk_ps)  HELD_downgrade=$held_dg"
