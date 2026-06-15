#!/bin/bash
set -euo pipefail

# =============================================================================
# Build + push V2 TEE_K and TEE_T container images, reproducibly.
#
# Same source + same commit = same image digest, every time. The router's
# APPROVED_IMAGE_DIGESTS list pins on digest, so reproducibility lets us
# rebuild from a specific commit in CI/audit and confirm the digest
# matches what's in production.
#
# Writes deploy/v2-digests.env with the resulting image URIs + digests so
# new-pair.sh / redeploy-fleet.sh can read them.
#
# Requirements:
#   - docker with buildx
#   - crane (go install github.com/google/go-containerregistry/cmd/crane@latest)
#
# Usage:
#   ./deploy/build-tees-v2.sh             # build HEAD
#   ./deploy/build-tees-v2.sh <commit>    # build a specific commit
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
cd "${REPO_ROOT}"

# Operator config lives in deploy/.env (gitignored). _lib.sh provides
# require_env_vars to fail fast if anything's missing.
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a; source "${SCRIPT_DIR}/.env"; set +a
fi
source "${SCRIPT_DIR}/_lib.sh"
require_env_vars GCP_PROJECT GCP_ZONE TEES_AR_REPO

PROJECT="${GCP_PROJECT}"
REGION="${GCP_ZONE%-*}"             # asia-south2-a → asia-south2
AR_HOST="${REGION}-docker.pkg.dev"
AR_REPO="${TEES_AR_REPO}"

# Reproducibility pin — independent of any deployment. Keep in sync with
# deploy/build.sh. Changing this changes layer hashes for the same source.
BUILDKIT_IMAGE="moby/buildkit:buildx-stable-1@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

COMMIT="${1:-$(git rev-parse HEAD)}"
COMMIT=$(git rev-parse "${COMMIT}")
SHORT="${COMMIT:0:7}"
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct "${COMMIT}")
log "Building from ${SHORT} (SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH})"

# Ensure AR repo exists — idempotent.
if ! gcloud artifacts repositories describe "${AR_REPO}" \
        --project="${PROJECT}" --location="${REGION}" >/dev/null 2>&1; then
    log "Creating AR repo ${AR_REPO}..."
    gcloud artifacts repositories create "${AR_REPO}" \
        --project="${PROJECT}" --location="${REGION}" \
        --repository-format=docker --quiet
fi

# Configure docker auth for AR push once per shell.
gcloud auth configure-docker "${AR_HOST}" --quiet >/dev/null 2>&1 || true

# Create/reuse the pinned-BuildKit builder. Without this, different host
# BuildKit versions can produce different layer hashes for the same
# source — breaking reproducibility. Reuse V1's builder name so existing
# state on the operator's machine carries over.
BUILDER_NAME="reclaim-repro"
if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    log "Creating pinned builder: ${BUILDER_NAME}"
    docker buildx create --name "${BUILDER_NAME}" --driver docker-container \
        --driver-opt image="${BUILDKIT_IMAGE}" \
        --bootstrap
fi
BUILDER_FLAG="--builder=${BUILDER_NAME}"

IMAGE_K_BASE="${AR_HOST}/${PROJECT}/${AR_REPO}/tee-k"
IMAGE_T_BASE="${AR_HOST}/${PROJECT}/${AR_REPO}/tee-t"
IMAGE_K_TAG="${IMAGE_K_BASE}:${SHORT}"
IMAGE_T_TAG="${IMAGE_T_BASE}:${SHORT}"

# Normalize file mtimes for reproducible layer hashes.
log "Normalizing mtimes to SOURCE_DATE_EPOCH..."
find . -path ./.git -prune -o -exec touch -d "@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null || true

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

# Build via buildx into OCI tarballs (deterministic), then push with
# crane (preserves the exact digest). Without crane, registry push can
# re-encode layers and change the digest.
log "Building TEE_K..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    --file=tee_k/Dockerfile.enclave \
    --tag="${IMAGE_K_TAG}" \
    --output="type=oci,dest=${TMPDIR}/tee-k.tar,rewrite-timestamp=true" \
    --build-arg=SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    . > /tmp/v2-build-k.log 2>&1 || { tail -50 /tmp/v2-build-k.log; exit 1; }

log "Building TEE_T..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    --file=tee_t/Dockerfile.enclave \
    --tag="${IMAGE_T_TAG}" \
    --output="type=oci,dest=${TMPDIR}/tee-t.tar,rewrite-timestamp=true" \
    --build-arg=SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    . > /tmp/v2-build-t.log 2>&1 || { tail -50 /tmp/v2-build-t.log; exit 1; }

mkdir -p "${TMPDIR}/tee-k-oci" "${TMPDIR}/tee-t-oci"
tar -xf "${TMPDIR}/tee-k.tar" -C "${TMPDIR}/tee-k-oci"
tar -xf "${TMPDIR}/tee-t.tar" -C "${TMPDIR}/tee-t-oci"

log "Pushing TEE_K → ${IMAGE_K_TAG}"
# crane push writes the resulting <image>@sha256:<digest> reference to
# stdout and progress logs to stderr. Capture stdout (final ref) while
# mirroring everything back to the terminal via `tee /dev/stderr`.
# Avoids a follow-up `crane digest` round-trip which can silently hang
# on AR eventual-consistency.
PUSH_K=$(crane push "${TMPDIR}/tee-k-oci" "${IMAGE_K_TAG}" 2>&1 | tee /dev/stderr | tail -1)
DIGEST_K="sha256:${PUSH_K##*@sha256:}"

log "Pushing TEE_T → ${IMAGE_T_TAG}"
PUSH_T=$(crane push "${TMPDIR}/tee-t-oci" "${IMAGE_T_TAG}" 2>&1 | tee /dev/stderr | tail -1)
DIGEST_T="sha256:${PUSH_T##*@sha256:}"

# Sanity-check that parsing didn't fall through to garbage.
case "${DIGEST_K}" in sha256:[0-9a-f]*) ;; *) echo "FATAL: failed to parse TEE_K digest from crane push output: ${PUSH_K}"; exit 1 ;; esac
case "${DIGEST_T}" in sha256:[0-9a-f]*) ;; *) echo "FATAL: failed to parse TEE_T digest from crane push output: ${PUSH_T}"; exit 1 ;; esac

cat > "${SCRIPT_DIR}/v2-digests.env" <<EOF
# Auto-generated by build-tees-v2.sh — do not edit by hand.
TEE_K_IMAGE=${IMAGE_K_BASE}@${DIGEST_K}
TEE_T_IMAGE=${IMAGE_T_BASE}@${DIGEST_T}
TEE_K_DIGEST=${DIGEST_K}
TEE_T_DIGEST=${DIGEST_T}
TEE_K_TAG=${IMAGE_K_TAG}
TEE_T_TAG=${IMAGE_T_TAG}
COMMIT=${COMMIT}
EOF

log "Build complete. K=${DIGEST_K:7:12}... T=${DIGEST_T:7:12}..."
