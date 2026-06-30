#!/bin/bash
LABEL="$1"; KIND="$2"; N="${3:-80}"
IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
cap=0; BREAK=0; held=0
for i in $(seq 1 $N); do
  MARK="/tmp/r4_proc/xm_${LABEL}_${i}.txt"; echo "X_${LABEL}_${i}_$RANDOM" > "$MARK"
  DEP="/tmp/r4_proc/xd_${LABEL}_${i}.rdep"
  if [ "$KIND" = "sig" ]; then $IOMON run --depfile "$DEP" -- /tmp/r4_proc/sigchild "$MARK" _exit >/dev/null 2>&1
  else $IOMON run --depfile "$DEP" -- /tmp/r4_proc/parent _exit "$MARK" fileaction >/dev/null 2>&1; fi
  OUT=$($IOMON inspect "$DEP" 2>/dev/null)
  mread=$(echo "$OUT"|grep -c "file-read.*$(basename $MARK)")
  comp=$(echo "$OUT"|grep -o 'completeness=[a-zA-Z]*'|head -1)
  if [ "$mread" -ge 1 ]; then cap=$((cap+1));
  elif [ "$comp" = "completeness=mcComplete" ]; then BREAK=$((BREAK+1)); cp "$DEP" "/tmp/r4_proc/BREAKX_${LABEL}_${i}.rdep" 2>/dev/null
  else held=$((held+1)); fi
  rm -f "$MARK" "$DEP"
done
echo "[$LABEL kind=$KIND N=$N] captured=$cap BREAK=$BREAK HELD_downgrade=$held"
