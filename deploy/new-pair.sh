#!/bin/bash
set -euo pipefail

# =============================================================================
# Spin up one new V2 TEE pair (one ${TEE_K_VM_PREFIX}-<n> + one ${TEE_T_VM_PREFIX}-<n>).
#
# Pair number is auto-assigned (lowest free <n>). Both VMs are
# Confidential Space, co-located in GCP_ZONE, get ephemeral external IPs,
# and dial each other over GCE internal DNS.
#
# After the VMs are up, polls the router /allocate endpoint until the
# pair reaches Ready (selector requires both sides to heartbeat with
# control_healthy + ot_ready true).
#
# APPROVED_IMAGE_DIGESTS on the router is auto-extended with this
# pair's digests if not already present.
#
# Requirements:
#   - deploy/v2-digests.env (run build-tees-v2.sh first)
#   - ROUTER_ADMIN_TOKEN env (the value of ADMIN_TOKEN on the router)
#
# Usage:
#   ./deploy/new-pair.sh             # auto-assign next free N
#   ./deploy/new-pair.sh --n 3       # use a specific N (parent script in
#                                    # parallel fan-out pre-computes Ns to
#                                    # avoid the auto-assign race)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auto-source deploy/.env (gitignored — copy from deploy/.env.example).
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a; source "${SCRIPT_DIR}/.env"; set +a
fi
source "${SCRIPT_DIR}/_lib.sh"
require_env_vars GCP_PROJECT GCP_ZONE ROUTER_URL ROUTER_JWT_ISSUER \
    TEE_NET_TAG TEE_K_VM_PREFIX TEE_T_VM_PREFIX TEE_PORT KMS_KEYRING \
    TEE_K_SA TEE_K_KMS_LOCATION TEE_K_KMS_KEY TEE_K_DEPLOYMENT_KEY \
    TEE_T_SA TEE_T_KMS_LOCATION TEE_T_KMS_KEY TEE_T_DEPLOYMENT_KEY \
    ROUTER_ADMIN_TOKEN

PROJECT="${GCP_PROJECT}"
ZONE="${GCP_ZONE}"
JWT_ISSUER="${ROUTER_JWT_ISSUER}"
PORT="${TEE_PORT}"
NET_TAG="${TEE_NET_TAG}"
# Public Google Confidential Space image family — not deployment-specific.
CS_IMAGE="projects/confidential-space-images/global/images/family/confidential-space"

[[ -f "${SCRIPT_DIR}/v2-digests.env" ]] || { echo "Missing ${SCRIPT_DIR}/v2-digests.env — run build-tees-v2.sh first"; exit 1; }
source "${SCRIPT_DIR}/v2-digests.env"

log() { echo "[$(date '+%H:%M:%S')] [pair=${N:-?}] $*"; }

N=""
SKIP_DIGEST_UPDATE=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --n) N="$2"; shift 2 ;;
        # Skip the in-script APPROVED_IMAGE_DIGESTS update. Parent
        # scripts (redeploy-fleet.sh) that run multiple new-pair.sh in
        # parallel pre-stage the env var once up front and pass this
        # flag — otherwise concurrent gcloud run services updates race
        # on Cloud Run's optimistic-concurrency version check.
        --skip-digest-update) SKIP_DIGEST_UPDATE=1; shift ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -z "${N}" ]]; then
    # Auto-assign next free pair number by scanning existing instances.
    # NOT safe for concurrent invocation — multiple processes scanning at
    # the same time will pick the same N. Parent scripts that fan out
    # should pre-compute Ns and pass --n explicitly.
    existing=$(gcloud_retry gcloud compute instances list \
        --project="${PROJECT}" --zones="${ZONE}" \
        --filter="name~^${TEE_K_VM_PREFIX}-" \
        --format="value(name)" 2>/dev/null | sed "s/.*${TEE_K_VM_PREFIX}-//" | sort -n)
    N=1
    while echo "${existing}" | grep -qx "${N}"; do N=$((N+1)); done
fi
log "Allocating pair number ${N}"

K_NAME="${TEE_K_VM_PREFIX}-${N}"
T_NAME="${TEE_T_VM_PREFIX}-${N}"
K_INTERNAL="${K_NAME}.${ZONE}.c.${PROJECT}.internal"
T_INTERNAL="${T_NAME}.${ZONE}.c.${PROJECT}.internal"

# Fetch JWT pubkey + admin token-gated APPROVED_IMAGE_DIGESTS — no need
# to copy these into the script.
JWT_PUBKEY=$(curl -sf "${ROUTER_URL}/jwt-pubkey")
[[ -n "${JWT_PUBKEY}" ]] || { echo "Failed to fetch /jwt-pubkey"; exit 1; }

# Make sure firewall + AR repo perms are wired (idempotent).
if ! gcloud_retry gcloud compute firewall-rules describe "${NET_TAG}-allow-${PORT}" \
        --project="${PROJECT}" >/dev/null 2>&1; then
    log "Creating firewall rule ${NET_TAG}-allow-${PORT}..."
    gcloud_retry gcloud compute firewall-rules create "${NET_TAG}-allow-${PORT}" \
        --project="${PROJECT}" \
        --direction=INGRESS \
        --action=ALLOW \
        --rules="tcp:${PORT}" \
        --target-tags="${NET_TAG}" \
        --source-ranges=0.0.0.0/0 --quiet
fi

# Extend router's allowlist BEFORE creating VMs. Uses the admin API
# (POST /allowlist) so updates are runtime-mutable — no Cloud Run
# revision swap, no in-flight TEE disconnect/re-register.
#
# Skipped when --skip-digest-update is passed — caller (redeploy-fleet)
# has already staged the digests once.
if [[ "${SKIP_DIGEST_UPDATE}" -eq 0 ]]; then
    log "Adding digests to router allowlist via admin API..."
    for d in "${TEE_K_DIGEST}" "${TEE_T_DIGEST}"; do
        curl -sf -X POST -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{\"digest\":\"${d}\"}" \
            "${ROUTER_URL}/allowlist" >/dev/null
    done
fi

create_vm() {
    local name=$1 image=$2 sa=$3 kms_loc=$4 kms_key=$5 deployment_key=$6 peer_addr=$7 peer_digest=$8
    log "Creating ${name}..."
    gcloud_retry gcloud compute instances create "${name}" \
        --project="${PROJECT}" --zone="${ZONE}" \
        --machine-type=n2d-standard-2 \
        --confidential-compute-type=SEV \
        --shielded-secure-boot \
        --shielded-vtpm \
        --shielded-integrity-monitoring \
        --maintenance-policy=TERMINATE \
        --image="${CS_IMAGE}" \
        --service-account="${sa}" \
        --scopes=cloud-platform \
        --tags="${NET_TAG}" \
        --network=default --subnet=default \
        --metadata="^|^\
tee-image-reference=${image}|\
tee-restart-policy=Never|\
tee-env-ROUTER_URL=${ROUTER_URL}|\
tee-env-PEER_ADDR=${peer_addr}|\
tee-env-EXPECTED_PEER_IMAGE_DIGEST=${peer_digest}|\
tee-env-JWT_PUBLIC_KEY=${JWT_PUBKEY}|\
tee-env-EXPECTED_JWT_ISSUER=${JWT_ISSUER}|\
tee-env-KMS_ENCLAVE_DOMAIN_KEY=${deployment_key}|\
tee-env-GOOGLE_PROJECT_ID=${PROJECT}|\
tee-env-GOOGLE_KMS_LOCATION=${kms_loc}|\
tee-env-GOOGLE_KMS_KEYRING=${KMS_KEYRING}|\
tee-env-GOOGLE_KMS_KEY=${kms_key}|\
tee-env-PORT=${PORT}" \
        --quiet
    # Label so retire-pair.sh and operators can identify the pair.
    local role
    case "${name}" in
        "${TEE_K_VM_PREFIX}"*) role=k ;;
        "${TEE_T_VM_PREFIX}"*) role=t ;;
        *) role=unknown ;;
    esac
    gcloud_retry gcloud compute instances add-labels "${name}" \
        --project="${PROJECT}" --zone="${ZONE}" \
        --labels="pair=${N},role=${role}" --quiet
}

# Create K and T concurrently. They dial each other over internal DNS so
# either-order startup is fine; `set -e` + explicit `wait` per PID makes
# either failure abort the script.
create_vm "${K_NAME}" "${TEE_K_IMAGE}" \
    "${TEE_K_SA}" \
    "${TEE_K_KMS_LOCATION}" "${TEE_K_KMS_KEY}" "${TEE_K_DEPLOYMENT_KEY}" \
    "${T_INTERNAL}:${PORT}" "${TEE_T_DIGEST}" &
PID_K=$!

create_vm "${T_NAME}" "${TEE_T_IMAGE}" \
    "${TEE_T_SA}" \
    "${TEE_T_KMS_LOCATION}" "${TEE_T_KMS_KEY}" "${TEE_T_DEPLOYMENT_KEY}" \
    "${K_INTERNAL}:${PORT}" "${TEE_K_DIGEST}" &
PID_T=$!

wait "${PID_K}"
wait "${PID_T}"

# Poll /pairs (admin) until THIS pair shows Ready. We identify our pair
# by the K VM's external IP — /pairs is the right endpoint for "is THIS
# pair ready", not /allocate (which picks ANY ready pair and is per-IP
# rate-limited; parallel new-pair.sh runs from one operator machine
# would 429 each other).
K_EXTERNAL_IP=$(gcloud_retry gcloud compute instances describe "${K_NAME}" \
    --project="${PROJECT}" --zone="${ZONE}" \
    --format='value(networkInterfaces[0].accessConfigs[0].natIP)')
log "Waiting for pair to reach Ready (teek_addr=${K_EXTERNAL_IP}:${PORT})..."
ready_start=$(date +%s)
READY=""
for i in {1..60}; do
    READY=$(curl -sf -H "Authorization: Bearer ${ROUTER_ADMIN_TOKEN}" "${ROUTER_URL}/pairs" \
        | jq -r --arg addr "${K_EXTERNAL_IP}:${PORT}" '
            .pairs[]
            | select(.teek_addr == $addr)
            | select(.ready_at != null and .ready_at != "")
            | .id' 2>/dev/null || true)
    if [[ -n "${READY}" ]]; then
        log "[pair=${N}] ready (pair_id=${READY}, $(( $(date +%s) - ready_start ))s)."
        break
    fi
    # Surface progress every ~16s so the wait doesn't read as a hang.
    if (( i % 8 == 0 )); then
        log "[pair=${N}] still waiting for Ready ($(( $(date +%s) - ready_start ))s, booting + OT precompute)..."
    fi
    sleep 2
done

if [[ -z "${READY}" ]]; then
    log "[pair=${N}] WARNING: pair did not reach Ready within $(( $(date +%s) - ready_start ))s; VMs are up but not serving."
fi

log "Done. Pair ${N}: ${K_NAME}, ${T_NAME}"
