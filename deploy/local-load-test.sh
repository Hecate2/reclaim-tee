#!/bin/bash
# Local load test — eliminates GCP/Confidential Space variables.
# Starts router + TEE_K + TEE_T as plain local binaries with pprof
# enabled, then hammers them with concurrent demo_standalone clients.
# Periodically snapshots heap + goroutine profiles so we can see
# memory growth and goroutine state evolve in real time.
#
# Usage:
#   ./deploy/local-load-test.sh                    # 500 total, 20 concurrent
#   ./deploy/local-load-test.sh 1000 50            # 1000 total, 50 concurrent
#   ./deploy/local-load-test.sh 2000 100 BUILD=1   # force rebuild
#
# Output: loadtest-local-<timestamp>/
#   ├── router.log, teek.log, teet.log         service stdout+stderr
#   ├── results.csv                            per-run (n, duration_ms, rc)
#   ├── runs/<n>.log                           per-client stdout
#   └── pprof/<unix_ts>/{heap,goroutine,allocs}.{teek,teet}.pb.gz
#                                              periodic profiles for analysis

set -uo pipefail

N="${1:-500}"
C="${2:-20}"
BUILD="${BUILD:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
cd "${REPO_ROOT}"

# Bypass any system proxy on outbound calls.
export http_proxy="" HTTP_PROXY=""
export https_proxy="" HTTPS_PROXY=""

ROUTER_PORT=9090
TEEK_PORT=8080
TEET_PORT=8081
ROUTER_URL=http://localhost:${ROUTER_PORT}
JWT_ISSUER="${ROUTER_JWT_ISSUER:?set ROUTER_JWT_ISSUER in deploy/.env}"

OUT_DIR="loadtest-local-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${OUT_DIR}/runs" "${OUT_DIR}/results"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Build if asked or if binaries are stale.
if [[ "${BUILD}" == "1" ]] || [[ ! -x bin/tee_k ]] || [[ ! -x bin/tee_t ]] || [[ ! -x bin/router ]] || [[ ! -x bin/client ]]; then
    log "Building..."
    ./build.sh > "${OUT_DIR}/build.log" 2>&1 || { tail "${OUT_DIR}/build.log"; exit 1; }
fi

# ─── Service teardown registered before anything starts ─────────────────
ROUTER_PID="" TEEK_PID="" TEET_PID=""
cleanup() {
    log "Shutting down services..."
    for var in ROUTER_PID TEEK_PID TEET_PID; do
        pid=${!var}
        [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null && kill "${pid}" 2>/dev/null
    done
    wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# ─── 1. Router ──────────────────────────────────────────────────────────
log "Starting router on :${ROUTER_PORT}..."
ROUTER_STANDALONE=true \
    JWT_ISSUER="${JWT_ISSUER}" \
    PORT="${ROUTER_PORT}" \
    ./bin/router > "${OUT_DIR}/router.log" 2>&1 &
ROUTER_PID=$!
for i in {1..30}; do
    curl -sf "${ROUTER_URL}/healthz" >/dev/null 2>&1 && break
    kill -0 ${ROUTER_PID} 2>/dev/null || { echo "router died"; tail "${OUT_DIR}/router.log"; exit 1; }
    sleep 0.2
done

JWT_PUBKEY=$(curl -sf "${ROUTER_URL}/jwt-pubkey")
[[ -z "${JWT_PUBKEY}" ]] && { echo "no jwt-pubkey"; exit 1; }

# GOGC is forwarded to both TEEs (env var). Default 100; set lower
# (e.g. GOGC=50) to force more aggressive GC — smaller peak heap,
# slightly higher CPU. Useful for testing the heap-vs-CPU tradeoff
# without code changes.
TEE_GOGC="${GOGC:-100}"
log "Using GOGC=${TEE_GOGC} for both TEEs"

# ─── 2. TEE_K ───────────────────────────────────────────────────────────
log "Starting TEE_K on :${TEEK_PORT}..."
GOGC="${TEE_GOGC}" \
    ROUTER_URL="${ROUTER_URL}" \
    SELF_ADDR="127.0.0.1:${TEEK_PORT}" \
    PEER_ADDR="127.0.0.1:${TEET_PORT}" \
    JWT_PUBLIC_KEY="${JWT_PUBKEY}" \
    EXPECTED_JWT_ISSUER="${JWT_ISSUER}" \
    PORT="${TEEK_PORT}" \
    ./bin/tee_k > "${OUT_DIR}/teek.log" 2>&1 &
TEEK_PID=$!

# ─── 3. TEE_T ───────────────────────────────────────────────────────────
log "Starting TEE_T on :${TEET_PORT}..."
GOGC="${TEE_GOGC}" \
    ROUTER_URL="${ROUTER_URL}" \
    SELF_ADDR="127.0.0.1:${TEET_PORT}" \
    PEER_ADDR="127.0.0.1:${TEEK_PORT}" \
    JWT_PUBLIC_KEY="${JWT_PUBKEY}" \
    EXPECTED_JWT_ISSUER="${JWT_ISSUER}" \
    PORT="${TEET_PORT}" \
    ./bin/tee_t > "${OUT_DIR}/teet.log" 2>&1 &
TEET_PID=$!

# ─── 4. Wait for /allocate to succeed (both TEEs registered + Ready) ────
log "Waiting for pair to reach Ready..."
for i in {1..60}; do
    kill -0 ${TEEK_PID} 2>/dev/null || { echo "tee_k died"; tail -50 "${OUT_DIR}/teek.log"; exit 1; }
    kill -0 ${TEET_PID} 2>/dev/null || { echo "tee_t died"; tail -50 "${OUT_DIR}/teet.log"; exit 1; }
    if curl -sf -X POST "${ROUTER_URL}/allocate" \
        -H "Content-Type: application/json" \
        -d '{"client_nonce":"probe"}' >/dev/null 2>&1; then
        log "Pair ready."
        break
    fi
    sleep 0.5
done

# ─── 5. Run the load ───────────────────────────────────────────────────
log "Starting load: ${N} total, ${C} concurrent..."

export OUT_DIR ROUTER_URL
run_one() {
    local n=$1
    local start_ms duration_ms rc
    start_ms=$(date +%s%3N)
    ./bin/client --router-url="${ROUTER_URL}" > "${OUT_DIR}/runs/${n}.log" 2>&1
    rc=$?
    duration_ms=$(( $(date +%s%3N) - start_ms ))
    printf '%d,%d,%d\n' "${n}" "${duration_ms}" "${rc}" > "${OUT_DIR}/results/${n}.csv"
    if [[ ${rc} -eq 0 ]]; then
        printf '[%s] run=%4d PASS  %5dms\n' "$(date '+%H:%M:%S')" "${n}" "${duration_ms}"
    else
        ERR=$(grep -m1 -E 'error|ERROR' "${OUT_DIR}/runs/${n}.log" | head -c 120)
        printf '[%s] run=%4d FAIL  %5dms rc=%d %s\n' "$(date '+%H:%M:%S')" "${n}" "${duration_ms}" "${rc}" "${ERR}"
    fi
}
export -f run_one

START_TS=$(date +%s)
seq 1 "${N}" | xargs -P "${C}" -n 1 -I {} bash -c 'run_one "$@"' _ {}
END_TS=$(date +%s)

# Final pprof snapshot — most useful for "after the load" analysis.
snapshot_pprof

log "Load complete in $((END_TS - START_TS))s. Aggregating..."
cat "${OUT_DIR}/results/"*.csv | sort -t, -k1,1n > "${OUT_DIR}/results.csv"

awk -F, '
    { rc=$3; dur=$2; total++ }
    rc==0 { pass++; durs[pass]=dur }
    rc!=0 { fail++; rcs[$3]++ }
    END {
        printf "Total: %d  Pass: %d (%.1f%%)  Fail: %d\n", total, pass, pass*100/total, fail
        if (pass>0) {
            n = asort(durs)
            printf "Latency: min=%dms p50=%dms p95=%dms p99=%dms max=%dms\n",
                durs[1], durs[int(n*0.5)], durs[int(n*0.95)], durs[int(n*0.99)], durs[n]
        }
    }' "${OUT_DIR}/results.csv" | tee "${OUT_DIR}/summary.txt"

echo ""
log "TEE_K log lines: $(wc -l < "${OUT_DIR}/teek.log")  TEE_T: $(wc -l < "${OUT_DIR}/teet.log")"
