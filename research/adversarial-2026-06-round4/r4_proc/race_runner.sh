#!/bin/bash
# race_runner.sh <label> <bin> <mode> <K> <N>
LABEL="$1"; BIN="$2"; MODE="$3"; K="$4"; N="${5:-60}"
IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
cap=0; BREAK=0; held_dg=0; brk_ps_durable=0
for i in $(seq 1 $N); do
  MARK="/tmp/r4_proc/rm_${LABEL}_${i}.txt"; echo "TK_${LABEL}_${i}_$RANDOM" > "$MARK"
  DEP="/tmp/r4_proc/rd_${LABEL}_${i}.rdep"
  $IOMON run --depfile "$DEP" -- /tmp/r4_proc/$BIN "$MARK" "$K" /tmp/r4_proc/junk.txt "$MODE" >/dev/null 2>&1
  OUT=$($IOMON inspect "$DEP" 2>/dev/null)
  mread=$(echo "$OUT"|grep -c "file-read.*$(basename $MARK)")
  comp=$(echo "$OUT"|grep -o 'completeness=[a-zA-Z]*'|head -1)
  # child's process-start = a process-start with pid != root. root spawn is #1 process-spawn child=PID.
  # count process-start lines (root has none labeled process-start except shim itself). Just count >0 distinct.
  psc=$(echo "$OUT"|grep -c 'process-start')
  if [ "$mread" -ge 1 ]; then cap=$((cap+1))
  elif [ "$comp" = "completeness=mcComplete" ]; then
    BREAK=$((BREAK+1))
    [ "$psc" -ge 1 ] && brk_ps_durable=$((brk_ps_durable+1))
    cp "$DEP" "/tmp/r4_proc/BREAK_${LABEL}_${i}.rdep"
  else held_dg=$((held_dg+1)); fi
  rm -f "$MARK" "$DEP"
done
echo "[$LABEL bin=$BIN mode=$MODE K=$K N=$N] captured=$cap  BREAK(lost+mcComplete)=$BREAK (ps_durable_in_breaks=$brk_ps_durable)  HELD_downgrade=$held_dg"
