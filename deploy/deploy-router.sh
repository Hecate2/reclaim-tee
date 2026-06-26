#!/bin/bash
set -euo pipefail

# =============================================================================
# Atomic Cloud Run deploy for the router service.
#
# Cloud Run gives us zero-downtime swap for free: the new revision boots,
# the platform hits its /healthz probe, and only then shifts 100% of traffic
# from the old revision to the new one. In-flight requests on the old
# revision drain naturally.
#
# State (Firestore + KMS) is external and shared across revisions, so the
# JWT signing key stays identical and TEEs don't need to refetch
# /jwt-pubkey on router redeploy.
#
# Usage:
#   ./deploy/deploy-router.sh             # build HEAD, deploy, verify
#   ./deploy/deploy-router.sh --skip-build  # redeploy existing image (whatever's currently tagged with HEAD short SHA)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
cd "${REPO_ROOT}"

if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a; source "${SCRIPT_DIR}/.env"; set +a
fi
source "${SCRIPT_DIR}/_lib.sh"
require_env_vars GCP_PROJECT GCP_ZONE ROUTER_URL ROUTER_SERVICE_NAME \
    ROUTER_AR_REPO ROUTER_JWT_ISSUER ROUTER_KMS_KEY_VERSION KMS_KEYRING

PROJECT="${GCP_PROJECT}"
REGION="${GCP_ZONE%-*}"
AR_HOST="${REGION}-docker.pkg.dev"
AR_REPO="${ROUTER_AR_REPO}"
SERVICE="${ROUTER_SERVICE_NAME}"
EXPECTED_JWT_ISSUER="${ROUTER_JWT_ISSUER}"

# KMS-backed signer for /allocate JWTs. Without this the router falls back
# to LocalSigner which generates a fresh keypair on every container start,
# invalidating every TEE's cached JWT_PUBLIC_KEY on every redeploy. The
# router-runtime SA already has roles/cloudkms.signer + publicKeyViewer
# on this key version. Pinned to a specific cryptoKeyVersion so a key
# rotation requires an explicit deploy-script edit, not a silent change.
KMS_KEY_NAME="projects/${PROJECT}/locations/${REGION}/keyRings/${KMS_KEYRING}/${ROUTER_KMS_KEY_VERSION}"

SKIP_BUILD=0
if [[ "${1:-}" == "--skip-build" ]]; then SKIP_BUILD=1; fi

# Refuse to deploy with uncommitted tracked changes — the image tag is the
# git short SHA, so a dirty tracked file would silently ship as that SHA.
# Untracked files (e.g. this script, local notes) are ignored.
if ! git diff-index --quiet HEAD --; then
    echo "ERROR: tracked files have uncommitted changes. Commit or stash before deploying."
    git status --short --untracked-files=no
    exit 1
fi

COMMIT=$(git rev-parse --short HEAD)
IMAGE="${AR_HOST}/${PROJECT}/${AR_REPO}/router:${COMMIT}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# 1. Build + push the container (or reuse if --skip-build).
if [[ $SKIP_BUILD -eq 1 ]]; then
    log "Skipping build, deploying existing image ${IMAGE}"
else
    log "Building router image ${IMAGE} via Cloud Build..."
    # gcloud builds submit's --tag mode requires Dockerfile at the build
    # context root. Ours is at router/Dockerfile (it COPIES the whole
    # repo because the router imports shared/+proto/), so pass an inline
    # cloudbuild config that points at the right Dockerfile.
    CLOUDBUILD_YAML=$(mktemp --suffix=.yaml)
    trap "rm -f ${CLOUDBUILD_YAML}" EXIT
    cat > "${CLOUDBUILD_YAML}" <<EOF
steps:
- name: gcr.io/cloud-builders/docker
  args: ['build', '-f', 'router/Dockerfile', '-t', '${IMAGE}', '.']
images:
- '${IMAGE}'
EOF
    gcloud builds submit \
        --project="${PROJECT}" \
        --config="${CLOUDBUILD_YAML}" \
        . > /tmp/router-build.log 2>&1 || {
            echo "Build failed; tail of /tmp/router-build.log:"
            tail -50 /tmp/router-build.log
            exit 1
        }
    log "Build complete."
fi

# 2. Capture the current revision name so we can compare against the new one.
PREV_REV=$(gcloud run services describe "${SERVICE}" \
    --project="${PROJECT}" --region="${REGION}" \
    --format='value(status.latestReadyRevisionName)')
log "Current revision: ${PREV_REV}"

# 3. Deploy. Cloud Run holds traffic on the old revision until the new one
# passes its startup probe; --revision-suffix makes the new revision name
# predictable for the verify step.
SUFFIX="${COMMIT}-$(date +%s)"
log "Deploying as revision suffix ${SUFFIX}..."
# --update-env-vars pins KMS_KEY_NAME, FIRESTORE_PROJECT_ID and the admin-token
# HASH without touching other env vars (SA_TOKEN_AUDIENCE / APPROVED_SA_PATTERN
# / JWT_ISSUER stay as configured).
#
# FIRESTORE_PROJECT_ID is critical: without it the router silently falls
# back to an in-memory Store, so pairs + allowlist are wiped on every
# revision swap. The `^|^` delimiter lets us pass values containing
# commas (the KMS key path) safely.
#
# The router stores only the admin token's SHA-256; derive it from
# ROUTER_ADMIN_TOKEN and strip any legacy plaintext ADMIN_TOKEN from the service.
ENV_VARS="KMS_KEY_NAME=${KMS_KEY_NAME}|FIRESTORE_PROJECT_ID=${PROJECT}"
if [[ -n "${ROUTER_ADMIN_TOKEN:-}" ]]; then
    ADMIN_TOKEN_HASH=$(printf %s "${ROUTER_ADMIN_TOKEN}" | sha256sum | cut -d' ' -f1)
    ENV_VARS="${ENV_VARS}|ADMIN_TOKEN_HASH=${ADMIN_TOKEN_HASH}"
fi
gcloud run deploy "${SERVICE}" \
    --project="${PROJECT}" \
    --region="${REGION}" \
    --image="${IMAGE}" \
    --revision-suffix="${SUFFIX}" \
    --update-env-vars="^|^${ENV_VARS}" \
    --remove-env-vars=ADMIN_TOKEN \
    --quiet

NEW_REV=$(gcloud run services describe "${SERVICE}" \
    --project="${PROJECT}" --region="${REGION}" \
    --format='value(status.latestReadyRevisionName)')
log "New revision: ${NEW_REV}"

if [[ "${NEW_REV}" == "${PREV_REV}" ]]; then
    echo "ERROR: latestReadyRevisionName did not change after deploy. Aborting."
    exit 1
fi

# 4. Verify the public URL is serving the new revision.
# /healthz returns JSON {status, standalone}. Production MUST have
# standalone=false; if it's true, a stray ROUTER_STANDALONE=true bled
# into the deploy and we want to fail loudly before declaring success.
log "Verifying ${ROUTER_URL}/healthz ..."
for i in {1..20}; do
    BODY=$(curl -sf "${ROUTER_URL}/healthz" 2>/dev/null || true)
    if [[ -n "${BODY}" ]]; then
        echo "  body: ${BODY}"
        if echo "${BODY}" | grep -q '"standalone":true'; then
            echo "ERROR: production router is in STANDALONE mode. Unset ROUTER_STANDALONE and redeploy."
            exit 1
        fi
        if echo "${BODY}" | grep -q '"status":"ok"'; then
            log "Healthz OK."
            break
        fi
    fi
    sleep 1
done

# 5. Sanity-check the JWT pubkey hasn't rotated (would indicate KMS key changed,
# which would invalidate every TEE-side EXPECTED_JWT_ISSUER + cached pubkey).
log "Fetching /jwt-pubkey ..."
PUBKEY=$(curl -sf "${ROUTER_URL}/jwt-pubkey" 2>/dev/null || true)
if [[ -z "${PUBKEY}" ]]; then
    echo "WARN: /jwt-pubkey returned empty. New endpoint may not be wired in deployed image."
elif [[ -f "${SCRIPT_DIR}/router-jwt-pubkey.pem" ]]; then
    if ! diff -q <(echo "${PUBKEY}") "${SCRIPT_DIR}/router-jwt-pubkey.pem" > /dev/null 2>&1; then
        echo "ERROR: router signing pubkey changed since previous deploy."
        echo "If this is expected (KMS key rotated), update deploy/router-jwt-pubkey.pem"
        echo "and redistribute JWT_PUBLIC_KEY to all TEEs."
        diff <(echo "${PUBKEY}") "${SCRIPT_DIR}/router-jwt-pubkey.pem" || true
        exit 1
    fi
    log "JWT pubkey matches deploy/router-jwt-pubkey.pem."
else
    log "First deploy with this script: snapshotting pubkey to deploy/router-jwt-pubkey.pem"
    echo "${PUBKEY}" > "${SCRIPT_DIR}/router-jwt-pubkey.pem"
fi

log "Done. ${PREV_REV} -> ${NEW_REV}"
