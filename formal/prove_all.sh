#!/usr/bin/env bash
# Prove each lemma in its own process so one hard lemma cannot starve the rest.
# Usage: ./prove_all.sh <file.spthy> [per-lemma timeout secs] [heap]
set -u
TAM=~/.local/tamarin
export PATH="$TAM/maudedir:$TAM:$PATH"
export MAUDE_LIB="$TAM/maudedir"

f=${1:?spthy file}
TIMEOUT=${2:-3600}
HEAP=${3:-8G}
log="${f%.spthy}.results"
: > "$log"

lemmas=$(grep -oP '^lemma \K[A-Za-z0-9_]+' "$f")
echo "file=$f timeout=${TIMEOUT}s heap=$HEAP" | tee -a "$log"
echo "lemmas: $(echo $lemmas | tr '\n' ' ')" | tee -a "$log"

for l in $lemmas; do
  start=$(date +%s)
  orc="${f%.spthy}.oracle"
  if [ -f "$orc" ]; then ohint=(--heuristic=o --oraclename="./$orc")
  else ohint=(--auto-sources); fi
  out=$(timeout "$TIMEOUT" tamarin-prover "$f" --prove="$l" "${ohint[@]}" \
          +RTS -M"$HEAP" -RTS 2>&1)
  rc=$?
  el=$(( $(date +%s) - start ))
  case $rc in
    124) res="TIMEOUT (${TIMEOUT}s)" ;;
    *)   res=$(echo "$out" | grep -E "^  $l " | head -1 | sed 's/^ *//')
         [ -z "$res" ] && res="ERROR rc=$rc: $(echo "$out" | grep -iE 'heap exhausted|error' | head -1)"
         ;;
  esac
  printf '%-38s %-6s %s\n' "$l" "${el}s" "$res" | tee -a "$log"
done
echo "=== done ===" | tee -a "$log"
