#!/bin/bash
set -euo pipefail

# =============================================================================
# Drain + delete one V2 TEE pair.
#
# Workflow:
#   1. Look up pair_id from the router by matching this pair's SELF_ADDR
#      (= external IP of tee-k-v2-<n>) against /pairs.
#   2. POST /pairs/{pair_id}/drain — router stops allocating to this pair.
#   3. Poll /pairs until active_sessions == 0 (or timeout — sessions are
#      short-lived, 1 min is more than enough).
#   4. POST /pairs/{pair_id}/dead — router evicts pair from its store.
#   5. Delete both VMs.
#
# Requirements:
#   - ROUTER_ADMIN_TOKEN env (admin endpoints are bearer-token-gated)
#
# Usage:
#   ./deploy/retire-pair.sh <n>          # retire pair number <n>
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a; source "${SCRIPT_DIR}/.env"; set +a
fi
source "${SCRIPT_DIR}/_lib.sh"
require_env_vars GCP_PROJECT GCP_ZONE ROUTER_URL \
    TEE_K_VM_PREFIX TEE_T_VM_PREFIX ROUTER_ADMIN_TOKEN

PROJECT="${GCP_PROJECT}"
ZONE="${GCP_ZONE}"
REGION="${ZONE%-*}"
# Drain rarely takes more than a few seconds — sessions are short-lived.
# Poll fast (250ms) so the script falls through immediately when drain
# is instant, instead of paying the 1-second sleep tax of the old loop.
DRAIN_TIMEOUT=${DRAIN_TIMEOUT:-60}        # seconds, hard ceiling
DRAIN_POLL_MS=${DRAIN_POLL_MS:-250}       # poll interval, milliseconds

N="${1:?usage: retire-pair.sh <n>}"
if ! [[ "${N}" =~ ^[0-9]+$ ]]; then
    echo "retire-pair.sh: pair number must be a positive integer, got: ${N}" >&2
    exit 1
fi
K_NAME="${TEE_K_VM_PREFIX}-${N}"
T_NAME="${TEE_T_VM_PREFIX}-${N}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Pull external IPs to identify the pair in router's /pairs view.
K_IP=$(gcloud_retry gcloud compute instances describe "${K_NAME}" --project="${PROJECT}" --zone="${ZONE}" \
    --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || true)
T_IP=$(gcloud_retry gcloud compute instances describe "${T_NAME}" --project="${PROJECT}" --zone="${ZONE}" \
    --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || true)

if [[ -z "${K_IP}" || -z "${T_IP}" ]]; then
    log "Could not locate VMs for pair ${N}; skipping router drain. Will delete what's left."
    PAIR_ID=""
else
    log "Pair ${N}: ${K_NAME}=${K_IP}, ${T_NAME}=${T_IP}"

    # Match pair(s) by teek_addr — port doesn't matter, IP uniquely
    # identifies the VM. Multiple rows can land on the same IP if a prior
    # /dead never reached Firestore (stale orphan). All of them route
    # traffic to this VM, so all must be drained + dead'd.
    mapfile -t PAIR_IDS < <(curl -sf -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" "${ROUTER_URL}/pairs" \
        | jq -r --arg ip "${K_IP}" '.pairs[] | select(.teek_addr | startswith($ip + ":")) | .id' \
        2>/dev/null || true)

    if [[ ${#PAIR_IDS[@]} -eq 0 ]]; then
        log "No matching pair in router for ${K_IP} — already retired? Skipping drain."
    else
        if [[ ${#PAIR_IDS[@]} -gt 1 ]]; then
            log "Found ${#PAIR_IDS[@]} pair_ids on ${K_IP} (stale orphans?); retiring all: ${PAIR_IDS[*]}"
        fi
        for PAIR_ID in "${PAIR_IDS[@]}"; do
            log "Draining pair_id ${PAIR_ID}..."
            curl -sf -X POST -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" \
                "${ROUTER_URL}/pairs/${PAIR_ID}/drain" >/dev/null || {
                log "WARN: drain returned non-zero for ${PAIR_ID} — continuing to /dead anyway"
            }

            # Poll every DRAIN_POLL_MS until active_sessions==0 or DRAIN_TIMEOUT.
            # First check runs IMMEDIATELY after drain — if there are no live
            # sessions the loop exits on iteration 0 with no sleep. Only log a
            # "still waiting" notice if it actually takes >1s.
            START=$(date +%s)
            LOGGED_WAIT=0
            ACTIVE=999
            MAX_ITERS=$(( DRAIN_TIMEOUT * 1000 / DRAIN_POLL_MS ))
            for i in $(seq 0 "${MAX_ITERS}"); do
                ACTIVE=$(curl -sf -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" "${ROUTER_URL}/pairs" \
                    | jq -r --arg id "${PAIR_ID}" '.pairs[] | select(.id == $id) | .active_sessions' \
                    2>/dev/null || echo 999)
                if [[ "${ACTIVE}" == "0" ]]; then
                    break
                fi
                if [[ ${LOGGED_WAIT} -eq 0 && $(( $(date +%s) - START )) -ge 1 ]]; then
                    log "Still draining (${ACTIVE} active sessions); will keep checking up to ${DRAIN_TIMEOUT}s..."
                    LOGGED_WAIT=1
                fi
                sleep "$(printf '%d.%03d' "$((DRAIN_POLL_MS/1000))" "$((DRAIN_POLL_MS%1000))")"
            done
            if [[ "${ACTIVE}" != "0" ]]; then
                log "WARN: pair still has ${ACTIVE} active sessions after ${DRAIN_TIMEOUT}s — forcing delete anyway."
            else
                log "Pair drained."
            fi

            # Mark pair dead — deletes the Firestore record so /pairs and the
            # selector stop seeing it. Retries on transient failures so a
            # network blip doesn't leave a stale row that lingers for ever.
            # 404 is treated as success (the doc was already gone).
            log "Marking pair dead..."
            for attempt in 1 2 3 4 5; do
                CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
                    -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" \
                    "${ROUTER_URL}/pairs/${PAIR_ID}/dead")
                case "${CODE}" in
                    204|404)
                        log "Marked dead (HTTP ${CODE})."
                        break
                        ;;
                    5*|000)
                        log "Transient /dead failure (HTTP ${CODE}); retry ${attempt}/5"
                        sleep $((attempt * 2))
                        ;;
                    *)
                        log "FATAL: /dead returned non-retryable HTTP ${CODE} for pair ${PAIR_ID}"
                        exit 1
                        ;;
                esac
                if [[ ${attempt} -eq 5 ]]; then
                    log "FATAL: /dead never succeeded for pair ${PAIR_ID} — Firestore will have a stale row; clean manually."
                    exit 1
                fi
            done
        done
    fi
fi

# Delete VMs. Both K and T independent — fan out so a flaky network on
# one doesn't serialize the other.
delete_vm() {
    local vm=$1
    if gcloud_retry gcloud compute instances describe "${vm}" --project="${PROJECT}" --zone="${ZONE}" >/dev/null 2>&1; then
        log "Deleting ${vm} (gcloud delete takes ~2 min)..."
        gcloud_retry gcloud compute instances delete "${vm}" --project="${PROJECT}" --zone="${ZONE}" --quiet
        log "Deleted ${vm}."
    fi
}
delete_vm "${K_NAME}" &
PID_K=$!
delete_vm "${T_NAME}" &
PID_T=$!

# gcloud instances delete blocks ~2 min with no output. Tick elapsed time
# every 15s while either child runs so the wait doesn't read as a hang.
del_start=$(date +%s)
while kill -0 "${PID_K}" 2>/dev/null || kill -0 "${PID_T}" 2>/dev/null; do
    sleep 15
    kill -0 "${PID_K}" 2>/dev/null || kill -0 "${PID_T}" 2>/dev/null || break
    log "  ...deleting VMs for pair ${N} ($(( $(date +%s) - del_start ))s elapsed)"
done
wait "${PID_K}"
wait "${PID_T}"

log "Pair ${N} retired."
