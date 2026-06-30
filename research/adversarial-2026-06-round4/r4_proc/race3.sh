#!/bin/bash
# race3.sh <label> <K> <N>  (child3: marker K junk mode=_exit ; worker reads marker, main _exit)
LABEL="$1"; K="$2"; N="${3:-80}"
IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
cap=0; BREAK=0; held_dg=0; brk_ps=0
for i in $(seq 1 $N); do
  MARK="/tmp/r4_proc/wm_${LABEL}_${i}.txt"; echo "WTK_${LABEL}_${i}_$RANDOM" > "$MARK"
  DEP="/tmp/r4_proc/wd_${LABEL}_${i}.rdep"
  $IOMON run --depfile "$DEP" -- /tmp/r4_proc/child3 "$MARK" "$K" /tmp/r4_proc/junk.txt _exit >/dev/null 2>&1
  OUT=$($IOMON inspect "$DEP" 2>/dev/null)
  mread=$(echo "$OUT"|grep -c "file-read.*$(basename $MARK)")
  comp=$(echo "$OUT"|grep -o 'completeness=[a-zA-Z]*'|head -1)
  psc=$(echo "$OUT"|grep -c 'process-start')
  if [ "$mread" -ge 1 ]; then cap=$((cap+1))
  elif [ "$comp" = "completeness=mcComplete" ]; then
    BREAK=$((BREAK+1)); [ "$psc" -ge 1 ] && brk_ps=$((brk_ps+1))
    cp "$DEP" "/tmp/r4_proc/BREAK3_${LABEL}_${i}.rdep" 2>/dev/null
  else held_dg=$((held_dg+1)); fi
  rm -f "$MARK" "$DEP"
done
echo "[$LABEL K=$K N=$N child3 worker-read/main-_exit] captured=$cap BREAK(lost+mcComplete)=$BREAK(ps=$brk_ps) HELD_downgrade=$held_dg"
