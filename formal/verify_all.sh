#!/usr/bin/env bash
# Verify every model. Writes formal/RESULTS.txt.
# Usage: ./verify_all.sh [per-lemma timeout secs] [heap]
set -u
cd "$(dirname "$0")"
TIMEOUT=${1:-1800}
HEAP=${2:-8G}
OUT=RESULTS.txt

MODELS=(
  correctness.spthy
  splitaead_privacy2.spthy
  request_privacy2.spthy
  invariants.spthy
  redaction.spthy
  redaction_negctl_appkey.spthy
  redaction_negctl_fullks.spthy
  transcript.spthy
  transcript_full.spthy
  transcript_negctl_nobinding.spthy
  transcript_negctl_nobinding_full.spthy
  rs_vs_teea_minimal.spthy
  bisect_a_withtag.spthy
)

{
  echo "split-AEAD formal verification -- full run"
  echo "tamarin-prover 1.12.0 / Maude 3.5.1   timeout=${TIMEOUT}s heap=$HEAP"
  echo
} > "$OUT"

for m in "${MODELS[@]}"; do
  echo "### $m" | tee -a "$OUT"
  ./prove_all.sh "$m" "$TIMEOUT" "$HEAP" 2>/dev/null | tail -n +3 | tee -a "$OUT"
  echo | tee -a "$OUT"
done

echo "wrote $OUT"
