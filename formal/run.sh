#!/usr/bin/env bash
# Tamarin runner with a hard memory cap so a runaway XOR unification
# cannot take down the machine. Usage: ./run.sh <file.spthy> [tamarin args...]
set -u
TAM=~/.local/tamarin
export PATH="$TAM/maudedir:$TAM:$PATH"
export MAUDE_LIB="$TAM/maudedir"
# ulimit -v is unusable: the GHC RTS reserves ~1TB of address space up front.
# Cap the Haskell heap instead; the RTS aborts cleanly when it is hit.
HEAP=${HEAP:-4G}
TIMEOUT=${TIMEOUT:-600}
f=$1; shift
timeout "$TIMEOUT" tamarin-prover "$f" "$@" +RTS -M"$HEAP" -RTS 2>&1
rc=$?
[ $rc -eq 124 ] && echo "=== TIMEOUT after ${TIMEOUT}s ==="
[ $rc -eq 137 ] && echo "=== KILLED (memory) ==="
exit $rc
