#!/bin/bash
set -euo pipefail

# =============================================================================
# Blue-green redeploy of the V2 TEE fleet.
#
#   1. Build new V2 images at HEAD (build-tees-v2.sh).
#   2. Append new digests to router's APPROVED_IMAGE_DIGESTS (in case
#      they aren't already there — new-pair.sh would add them anyway).
#   3. Spin up N new pairs via new-pair.sh (parallel-safe via pair-number
#      auto-assignment).
#   4. Wait until all N new pairs are Ready in the router.
#   5. Retire all OLD pairs (image_digest != new) via retire-pair.sh.
#   6. Trim old digests from APPROVED_IMAGE_DIGESTS.
#
# Use this for redeploys. For initial deploy (no V2 pairs yet) it works
# too — step 5 finds nothing to retire and exits cleanly.
#
# For pure capacity scale-up (no redeploy), skip this and just run
# new-pair.sh N times.
#
# Requirements:
#   - docker + crane (for build)
#   - ROUTER_ADMIN_TOKEN env
#
# Usage:
#   ./deploy/redeploy-fleet.sh --count 2     # full redeploy at fleet size 2
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a; source "${SCRIPT_DIR}/.env"; set +a
fi
source "${SCRIPT_DIR}/_lib.sh"
require_env_vars GCP_PROJECT GCP_ZONE ROUTER_URL \
    TEE_K_VM_PREFIX ROUTER_ADMIN_TOKEN

PROJECT="${GCP_PROJECT}"
ZONE="${GCP_ZONE}"
REGION="${ZONE%-*}"

COUNT=2
FORCE_REBUILD=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --count) COUNT="$2"; shift 2 ;;
        # Skip the deterministic-build check and rebuild unconditionally.
        # Useful if the build environment changed (BuildKit version pin,
        # Dockerfile, etc.) and you want fresh images even at the same commit.
        --force-rebuild) FORCE_REBUILD=1; shift ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# 1. Build — but skip if deploy/v2-digests.env's COMMIT matches HEAD.
# Builds are deterministic (mtimes normalized + pinned BuildKit + same
# source = same layer hashes), so re-running just to re-derive the
# same digests is wasted minutes. Operator can force with --force-rebuild.
CURRENT_COMMIT=$(git rev-parse HEAD)
SKIP_BUILD=0
if [[ ${FORCE_REBUILD} -eq 0 && -f "${SCRIPT_DIR}/v2-digests.env" ]]; then
    # Read the cached commit without polluting the current shell.
    CACHED_COMMIT=$(grep -E '^COMMIT=' "${SCRIPT_DIR}/v2-digests.env" | cut -d= -f2- || true)
    if [[ "${CACHED_COMMIT}" == "${CURRENT_COMMIT}" ]]; then
        log "Cached build matches HEAD (${CURRENT_COMMIT:0:7}); skipping build."
        SKIP_BUILD=1
    else
        log "Cached build is for ${CACHED_COMMIT:0:7}; HEAD is ${CURRENT_COMMIT:0:7}; rebuilding."
    fi
fi
if [[ ${SKIP_BUILD} -eq 0 ]]; then
    log "Building new V2 images..."
    "${SCRIPT_DIR}/build-tees-v2.sh"
fi
source "${SCRIPT_DIR}/v2-digests.env"
log "Digests: K=${TEE_K_DIGEST:7:12}... T=${TEE_T_DIGEST:7:12}..."

# 2. Snapshot old pair numbers BEFORE creating new ones, so retire only
# touches the pre-existing fleet. Pre-compute the COUNT lowest-free Ns to
# hand into the parallel new-pair.sh fan-out — keeps the auto-assign race
# entirely out of the picture.
OLD_NS=$(gcloud_retry gcloud compute instances list \
    --project="${PROJECT}" --zones="${ZONE}" \
    --filter="name~^${TEE_K_VM_PREFIX}-" \
    --format="value(name)" 2>/dev/null | sed "s/.*${TEE_K_VM_PREFIX}-//" | sort -n)
# Defensive: keep only integer lines. If anything garbage ever slips in
# (gcloud warning bleeding through stderr, format change, etc.) we don't
# want it word-split into the retire-pair loop. Each remaining line is
# a numeric pair index.
OLD_NS=$(echo "${OLD_NS}" | grep -E '^[0-9]+$' || true)
log "Old pairs: ${OLD_NS:-<none>}"

NEW_NS=()
N=1
while [[ ${#NEW_NS[@]} -lt ${COUNT} ]]; do
    if ! echo "${OLD_NS}" | grep -qx "${N}"; then
        NEW_NS+=("${N}")
    fi
    N=$((N+1))
done
log "New pair numbers: ${NEW_NS[*]}"

# Pre-stage the new digests in the router's allowlist via admin API.
# Runtime mutation — no Cloud Run revision swap, no TEE disconnect.
# Children pass --skip-digest-update so the writes happen once here
# and parallel new-pair.sh runs don't repeat them.
log "Adding new digests to router allowlist via admin API..."
for d in "${TEE_K_DIGEST}" "${TEE_T_DIGEST}"; do
    curl -sf -X POST -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"digest\":\"${d}\"}" \
        "${ROUTER_URL}/allowlist" >/dev/null
done

# 3. Spin up N new pairs in parallel — each new-pair.sh internally also
# parallelizes K+T VM creates, so wall-clock is bounded by the slowest
# single VM boot, not COUNT*2*boot_time. --skip-digest-update prevents
# children from racing on the env var we just pre-staged.
log "Spinning up ${COUNT} new pairs in parallel..."
NEW_PIDS=()
for n in "${NEW_NS[@]}"; do
    "${SCRIPT_DIR}/new-pair.sh" --n "${n}" --skip-digest-update &
    NEW_PIDS+=($!)
done
# Emit a "." every 5s while any child is still running so the terminal
# shows liveness — without this, a slower child looks like a hang
# (the parent is just blocked in wait, child is running silently after
# its own "Done" line).
# Emit an elapsed-time line every ~15s while a backgrounded child runs, so a
# long-but-working phase (VM boot, OT precompute, gcloud delete) reads as
# progress rather than a hang. The child's own log lines interleave.
heartbeat_until_done() {
    local pid=$1
    local label="${2:-task}"
    local start
    start=$(date +%s)
    while kill -0 "${pid}" 2>/dev/null; do
        sleep 15
        kill -0 "${pid}" 2>/dev/null || break
        log "  ...${label} still running ($(( $(date +%s) - start ))s elapsed)"
    done
}
for pid in "${NEW_PIDS[@]}"; do
    heartbeat_until_done "${pid}" "new pair bringup"
    wait "${pid}"
done

# 4. new-pair.sh already waits for Ready, so we know all N new are
# allocatable at this point. Sanity-check by counting Ready pairs.
log "Verifying fleet is up to ${COUNT} new pairs..."
NEW_READY=$(curl -sf -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" "${ROUTER_URL}/pairs" \
    | python3 -c "
import json, sys
data = json.load(sys.stdin)
new_digest = '${TEE_K_DIGEST}'
# ready_at is omitzero — present iff pair has reached Ready at least once.
n = sum(1 for p in data.get('pairs', [])
        if p.get('teek_image_digest') == new_digest
        and not p.get('draining', False)
        and p.get('ready_at'))
print(n)
")
if [[ "${NEW_READY}" -lt "${COUNT}" ]]; then
    log "ERROR: only ${NEW_READY}/${COUNT} new pairs are Ready. Aborting before retiring old."
    exit 1
fi
log "${NEW_READY} new pairs Ready."

# 5. Retire old pairs in parallel — each retire-pair.sh drains its own
# pair independently and the drains can happen concurrently.
if [[ -z "${OLD_NS}" ]]; then
    log "No old pairs to retire."
else
    log "Retiring old pairs in parallel: ${OLD_NS}"
    RETIRE_PIDS=()
    RETIRE_NS=()
    for n in ${OLD_NS}; do
        "${SCRIPT_DIR}/retire-pair.sh" "${n}" &
        RETIRE_PIDS+=($!)
        RETIRE_NS+=("${n}")
    done
    # Run every retire to completion and only fail at the end. With `set -e`
    # plus `wait $pid`, an earlier failing pid would abort the parent loop
    # and leave later pids' results unobserved — masking the partial state.
    RETIRE_FAILED=()
    for i in "${!RETIRE_PIDS[@]}"; do
        pid="${RETIRE_PIDS[$i]}"
        n="${RETIRE_NS[$i]}"
        heartbeat_until_done "${pid}" "retiring pair ${n}"
        if ! wait "${pid}"; then
            RETIRE_FAILED+=("${n}")
            log "ERROR: retire-pair.sh ${n} failed (pid ${pid}, exit non-zero)"
        fi
    done
    if [[ ${#RETIRE_FAILED[@]} -gt 0 ]]; then
        log "FATAL: ${#RETIRE_FAILED[@]} pair(s) failed to retire: ${RETIRE_FAILED[*]}"
        log "Re-run ./deploy/retire-pair.sh <n> for each, then trim the allowlist by hand."
        exit 1
    fi
fi

# 6. Trim old digests from the allowlist via admin API. List → keep only
# the new K+T digests → DELETE everything else. Admin API mutation, no
# router revision swap.
log "Trimming allowlist to current digests via admin API..."
CURRENT_LIST=$(curl -sf -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" \
    "${ROUTER_URL}/allowlist" | jq -r '.digests[]')
for d in ${CURRENT_LIST}; do
    case "${d}" in
        "${TEE_K_DIGEST}"|"${TEE_T_DIGEST}") ;;
        *)
            log "Removing old digest ${d:0:24}..."
            # ':' is a valid URL path character; Go ServeMux's {digest}
            # captures the segment as-is and the handler URL-unescapes.
            curl -sf -X DELETE -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" \
                "${ROUTER_URL}/allowlist/${d}" >/dev/null
            ;;
    esac
done

log "Fleet redeploy complete. ${COUNT} pairs at ${TEE_K_DIGEST:0:19}.../${TEE_T_DIGEST:0:19}..."
