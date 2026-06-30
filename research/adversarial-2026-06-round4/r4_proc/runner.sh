#!/bin/bash
# runner.sh <label> <child-mode> <spawn-style> <iterations>
LABEL="$1"; CMODE="$2"; STYLE="$3"; N="${4:-40}"
IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
break_count=0; held_read=0; downgrade=0; ps_missing=0; notcomplete=0
for i in $(seq 1 $N); do
  MARK="/tmp/r4_proc/m_${LABEL}_${i}_$RANDOM.txt"
  TOK="TOKEN_${LABEL}_${i}_$RANDOM"
  echo "$TOK" > "$MARK"
  DEP="/tmp/r4_proc/d_${LABEL}_${i}.rdep"
  $IOMON run --depfile "$DEP" -- /tmp/r4_proc/parent "$CMODE" "$MARK" "$STYLE" >/dev/null 2>&1
  OUT=$($IOMON inspect "$DEP" 2>/dev/null)
  # did the child's read of THIS marker get captured?
  read_present=$(echo "$OUT" | grep -c "file-read.*$(basename $MARK)")
  comp=$(echo "$OUT" | grep -o "completeness=[a-zA-Z]*" | head -1)
  # was a process-start recorded for a child (pid != root)? count process-start lines
  ps_count=$(echo "$OUT" | grep -c "process-start")
  loss=$(echo "$OUT" | grep -o "eventLoss=[0-9]*" | head -1)
  dgrade=$(echo "$OUT" | grep -ci "downgrad\|incomplete\|mcIncomplete\|mcUnknown")
  if [ "$read_present" -eq 0 ]; then
    if [ "$comp" = "completeness=mcComplete" ]; then
      break_count=$((break_count+1))
      if [ "$ps_count" -ge 2 ]; then : ; else ps_missing=$((ps_missing+1)); fi
    else
      notcomplete=$((notcomplete+1))
    fi
  else
    held_read=$((held_read+1))
  fi
  rm -f "$MARK"
done
echo "[$LABEL mode=$CMODE style=$STYLE N=$N] read_captured=$held_read  BREAK(read_missing+mcComplete)=$break_count  read_missing_but_NOT_complete=$notcomplete  (of breaks, ps<2 cnt=$ps_missing)"
