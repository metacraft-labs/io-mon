#!/bin/bash
# Rigorous checker via inspect TEXT output. Args: prog, nmarkers, runs, label
PROG="$1"; NMARK="$2"; RUNS="$3"; LABEL="$4"; ARG="${5:-/tmp/r3_merge/markers}"
IOMON=/Users/zahary/m/dev/io-mon/build/bin/io-mon
breaks=0; fincomplete=0; ok=0
for run in $(seq 1 $RUNS); do
  dep=/tmp/r3_merge/chk_$run.rdep
  $IOMON run --depfile $dep -- "$PROG" "$ARG" >/dev/null 2>&1
  txt=$($IOMON inspect $dep 2>/dev/null)
  comp=$(printf '%s' "$txt" | head -1 | grep -oE 'mc[A-Za-z]+')
  got=$(printf '%s' "$txt" | grep -oE 'marker_[0-9]+\.txt' | sort -u | wc -l | tr -d ' ')
  if [ "$got" -lt "$NMARK" ] && [ "$comp" = mcComplete ]; then
    echo "BREAK $LABEL run=$run captured=$got/$NMARK comp=$comp"; breaks=$((breaks+1))
  elif [ "$got" -eq "$NMARK" ] && [ "$comp" != mcComplete ]; then
    echo "FALSE-INCOMPLETE $LABEL run=$run captured=$got/$NMARK comp=$comp"; fincomplete=$((fincomplete+1))
  else ok=$((ok+1)); fi
  rm -f $dep
done
echo "$LABEL: runs=$RUNS ok=$ok BREAKS=$breaks FALSE-INCOMPLETE=$fincomplete"
