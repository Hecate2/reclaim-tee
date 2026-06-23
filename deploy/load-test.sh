#!/bin/bash
# Run N proofs with up to C concurrently. Captures per-run pass/fail +
# wall-clock latency, then prints aggregate stats (pass rate, p50/p95/p99).
#
# Each child writes a CSV row `n,duration_ms,rc` to its own file under
# loadtest-out/results/ — no shared-file locking needed. Per-run stdout
# goes to loadtest-out/runs/<n>.log so any failure can be inspected
# without grepping the global log.
#
# Defaults: N=100 total, C=10 concurrent.
#
# Usage:
#   ./deploy/load-test.sh             # 100 / 10
#   ./deploy/load-test.sh 200 20      # 200 total, 20 concurrent
#   ./deploy/load-test.sh 100 10 BUILD=1   # force rebuild before running

set -uo pipefail

N="${1:-100}"
C="${2:-10}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
cd "${REPO_ROOT}"

# Bypass any local proxy (the dev machine's loopback proxy resets under load).
export http_proxy=""  HTTP_PROXY=""
export https_proxy="" HTTPS_PROXY=""
export all_proxy=""   ALL_PROXY=""

# Build once if the binary is missing OR the operator asked for it.
if [[ ! -x bin/sample_app_shared ]] || [[ "${BUILD:-0}" == "1" ]]; then
    echo "[$(date '+%H:%M:%S')] Building lib + sample app..."
    ./lib.sh build > /tmp/loadtest-build.log 2>&1 || {
        echo "BUILD FAILED — see /tmp/loadtest-build.log"
        exit 1
    }
fi

OUT_DIR="loadtest-out-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${OUT_DIR}/runs" "${OUT_DIR}/results"

export LD_LIBRARY_PATH="${REPO_ROOT}/bin:${LD_LIBRARY_PATH:-}"
export OUT_DIR

echo "[$(date '+%H:%M:%S')] Starting load test: ${N} proofs, ${C} concurrent. Output: ${OUT_DIR}/"

# Child runner. xargs spawns up to C of these in parallel.
run_one() {
    local n=$1
    local start_ms duration_ms rc
    start_ms=$(date +%s%3N)
    ( cd bin && ./sample_app_shared ) > "${OUT_DIR}/runs/${n}.log" 2>&1
    rc=$?
    duration_ms=$(( $(date +%s%3N) - start_ms ))
    printf '%d,%d,%d\n' "${n}" "${duration_ms}" "${rc}" > "${OUT_DIR}/results/${n}.csv"
    if [[ ${rc} -eq 0 ]]; then
        printf '[%s] run=%4d PASS  %5dms\n' "$(date '+%H:%M:%S')" "${n}" "${duration_ms}"
    else
        printf '[%s] run=%4d FAIL  %5dms rc=%d\n' "$(date '+%H:%M:%S')" "${n}" "${duration_ms}" "${rc}"
    fi
}
export -f run_one
export OUT_DIR

START_TS=$(date +%s)
seq 1 "${N}" | xargs -P "${C}" -n 1 -I {} bash -c 'run_one "$@"' _ {}
END_TS=$(date +%s)

echo ""
echo "[$(date '+%H:%M:%S')] All ${N} runs complete in $((END_TS - START_TS))s. Aggregating..."

# Merge per-run CSVs.
cat "${OUT_DIR}/results/"*.csv | sort -t, -k1,1n > "${OUT_DIR}/results.csv"

# Stats via awk: pass count, fail count, p50/p95/p99 over PASSED runs only.
awk -F, '
    { rc=$3; dur=$2; total++ }
    rc==0 { pass++; durs[pass]=dur }
    rc!=0 { fail++; rcs[$3]++ }
    END {
        if (total == 0) { print "no results"; exit 1 }
        printf "Total:    %d\n", total
        printf "Pass:     %d (%.1f%%)\n", pass, pass*100/total
        printf "Fail:     %d (%.1f%%)\n", fail, fail*100/total
        if (pass > 0) {
            # Sort durs ascending.
            n = asort(durs)
            p50 = durs[int(n*0.50 + 0.999)]
            p95 = durs[int(n*0.95 + 0.999)]
            p99 = durs[int(n*0.99 + 0.999)]
            printf "Latency (passed runs):\n"
            printf "  min:  %5dms\n", durs[1]
            printf "  p50:  %5dms\n", p50
            printf "  p95:  %5dms\n", p95
            printf "  p99:  %5dms\n", p99
            printf "  max:  %5dms\n", durs[n]
        }
        if (fail > 0) {
            printf "Exit codes seen on failures:\n"
            for (rc in rcs) printf "  rc=%s: %d\n", rc, rcs[rc]
        }
    }' "${OUT_DIR}/results.csv" | tee "${OUT_DIR}/summary.txt"

# Surface the first failure's error line for quick diagnosis.
if grep -q ',[^0]$' "${OUT_DIR}/results.csv"; then
    FIRST_FAIL=$(awk -F, '$3!=0 {print $1; exit}' "${OUT_DIR}/results.csv")
    echo ""
    echo "First failure was run ${FIRST_FAIL}. Sample error lines:"
    grep -m3 -E 'error|ERROR|SECURITY|failed' "${OUT_DIR}/runs/${FIRST_FAIL}.log" | head -3 | sed 's/^/  /'
fi
