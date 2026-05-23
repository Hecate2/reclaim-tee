#!/bin/bash
set -e

# =============================================================================
# RECLAIM TEE BUILD SCRIPT - REPRODUCIBLE UNIFIED IMAGES
# =============================================================================
# Builds and pushes reproducible tee-k and tee-t images.
# Same source code + same commit = same image digest, always.
#
# Flow: build OCI tarball (deterministic) -> push with crane (preserves digest)
#
# Requirements:
#   - Docker with buildx
#   - crane (go install github.com/google/go-containerregistry/cmd/crane@latest)
#   - deploy/build.env with REGISTRY
#
# Usage:
#   ./build.sh [tag] [commit] [--verify]
#   ./build.sh                     # tag=v2, commit=HEAD
#   ./build.sh v3                  # explicit tag, commit=HEAD
#   ./build.sh v3 abc123           # explicit tag + commit (for rebuilding)
#   ./build.sh v3 --verify         # build + verify reproducibility
#   ./build.sh v3 abc123 --verify  # rebuild from specific commit + verify
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"

# Pinned BuildKit image for reproducible builds across environments
# Update this digest when upgrading BuildKit (run: docker pull moby/buildkit:buildx-stable-1)
BUILDKIT_IMAGE="moby/buildkit:buildx-stable-1@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"

# Load config from build.env (not committed to git)
BUILD_ENV="${SCRIPT_DIR}/build.env"
if [[ ! -f "${BUILD_ENV}" ]]; then
    echo "Missing ${BUILD_ENV}. Create it with:"
    echo "  REGISTRY=gcr.io/your-project"
    exit 1
fi
source "${BUILD_ENV}"

# Validate required config
: "${REGISTRY:?REGISTRY not set in build.env}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo "[ERROR] $1" >&2
    exit 1
}

IMAGE_TAG="${1:-v2}"
COMMIT="${2:-}"
VERIFY="${3:-}"

# If no commit supplied, also accept --verify as second arg
if [[ "${COMMIT}" == "--verify" ]]; then
    VERIFY="--verify"
    COMMIT=""
fi

IMAGE_TK="${REGISTRY}/tee-k:${IMAGE_TAG}"
IMAGE_TT="${REGISTRY}/tee-t:${IMAGE_TAG}"

# Use supplied commit or HEAD for SOURCE_DATE_EPOCH
if [[ -n "${COMMIT}" ]]; then
    export SOURCE_DATE_EPOCH=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct "${COMMIT}")
    log "Using SOURCE_DATE_EPOCH from commit ${COMMIT}: ${SOURCE_DATE_EPOCH}"
else
    COMMIT=$(git -C "${REPO_ROOT}" rev-parse HEAD)
    export SOURCE_DATE_EPOCH=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct)
    log "Using SOURCE_DATE_EPOCH from HEAD (${COMMIT:0:12}): ${SOURCE_DATE_EPOCH}"
fi

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

# Check crane is available
command -v crane >/dev/null 2>&1 || error "crane not found. Install: go install github.com/google/go-containerregistry/cmd/crane@latest"

# Normalize file mtimes to SOURCE_DATE_EPOCH for reproducibility.
# Git checkout sets mtimes to checkout time, which varies between environments.
find "${REPO_ROOT}" -not -path '*/.git/*' -exec touch -d "@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null || true

# Create/reuse pinned builder
BUILDER_NAME="reclaim-repro"
if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    log "Creating pinned builder: ${BUILDER_NAME}"
    docker buildx create --name "${BUILDER_NAME}" --driver docker-container \
        --driver-opt image="${BUILDKIT_IMAGE}" \
        --bootstrap
fi
BUILDER_FLAG="--builder=${BUILDER_NAME}"

log "Building reproducible images (tag: ${IMAGE_TAG}, SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH})"
log "  TEE-K: ${IMAGE_TK}"
log "  TEE-T: ${IMAGE_TT}"

# Build as OCI tarballs (deterministic output)
log "Building TEE-K..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    -f "${REPO_ROOT}/tee_k/Dockerfile.enclave" \
    -o type=oci,dest="${TMPDIR}/tee-k.tar",rewrite-timestamp=true \
    "${REPO_ROOT}"

log "Building TEE-T..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    -f "${REPO_ROOT}/tee_t/Dockerfile.enclave" \
    -o type=oci,dest="${TMPDIR}/tee-t.tar",rewrite-timestamp=true \
    "${REPO_ROOT}"

log "Both images built"

# Extract OCI layouts for crane push
mkdir -p "${TMPDIR}/tee-k-oci" "${TMPDIR}/tee-t-oci"
tar -xf "${TMPDIR}/tee-k.tar" -C "${TMPDIR}/tee-k-oci"
tar -xf "${TMPDIR}/tee-t.tar" -C "${TMPDIR}/tee-t-oci"

# Push with crane (preserves exact digest from build)
log "Pushing TEE-K..."
crane push "${TMPDIR}/tee-k-oci" "${IMAGE_TK}"

log "Pushing TEE-T..."
crane push "${TMPDIR}/tee-t-oci" "${IMAGE_TT}"

log "Images pushed"

# Print digests
DIGEST_TK=$(crane digest "${IMAGE_TK}")
DIGEST_TT=$(crane digest "${IMAGE_TT}")

echo ""
echo "============================================="
echo "Image Digests:"
echo "  TEE-K: ${DIGEST_TK}"
echo "  TEE-T: ${DIGEST_TT}"
echo "============================================="

# Optional: verify reproducibility by rebuilding locally
if [[ "${VERIFY}" == "--verify" ]]; then
    log "Verifying reproducibility (rebuilding from scratch)..."

    log "Rebuilding TEE-K..."
    docker buildx build ${BUILDER_FLAG} --no-cache \
        -f "${REPO_ROOT}/tee_k/Dockerfile.enclave" \
        -o type=oci,dest="${TMPDIR}/verify-tk.tar",rewrite-timestamp=true \
        "${REPO_ROOT}"

    log "Rebuilding TEE-T..."
    docker buildx build ${BUILDER_FLAG} --no-cache \
        -f "${REPO_ROOT}/tee_t/Dockerfile.enclave" \
        -o type=oci,dest="${TMPDIR}/verify-tt.tar",rewrite-timestamp=true \
        "${REPO_ROOT}"

    echo ""
    echo "Reproducibility Verification:"

    HASH_TK_ORIG=$(sha256sum "${TMPDIR}/tee-k.tar" | cut -d' ' -f1)
    HASH_TK_VERIFY=$(sha256sum "${TMPDIR}/verify-tk.tar" | cut -d' ' -f1)
    echo "  TEE-K build 1: ${HASH_TK_ORIG}"
    echo "  TEE-K build 2: ${HASH_TK_VERIFY}"
    if [[ "${HASH_TK_ORIG}" == "${HASH_TK_VERIFY}" ]]; then
        echo "  TEE-K: MATCH"
    else
        echo "  TEE-K: MISMATCH"
    fi

    HASH_TT_ORIG=$(sha256sum "${TMPDIR}/tee-t.tar" | cut -d' ' -f1)
    HASH_TT_VERIFY=$(sha256sum "${TMPDIR}/verify-tt.tar" | cut -d' ' -f1)
    echo "  TEE-T build 1: ${HASH_TT_ORIG}"
    echo "  TEE-T build 2: ${HASH_TT_VERIFY}"
    if [[ "${HASH_TT_ORIG}" == "${HASH_TT_VERIFY}" ]]; then
        echo "  TEE-T: MATCH"
    else
        echo "  TEE-T: MISMATCH"
    fi
fi
