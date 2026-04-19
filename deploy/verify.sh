#!/bin/bash
set -e

# =============================================================================
# RECLAIM TEE IMAGE VERIFICATION
# =============================================================================
# Rebuilds TEE images from source and verifies the digests match the ones
# recorded in deploy/image-history.json. No GCP credentials needed.
#
# Uses the same pinned BuildKit image as build.sh to ensure identical output.
#
# Requirements:
#   - Docker with buildx
#
# Usage:
#   ./verify.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
HISTORY="${SCRIPT_DIR}/image-history.json"

# Same pinned BuildKit image as build.sh -- must match exactly
BUILDKIT_IMAGE="moby/buildkit:buildx-stable-1@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5"

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

if [[ ! -f "${HISTORY}" ]]; then
    echo "ERROR: ${HISTORY} not found"
    exit 1
fi

# Check for empty history
ENTRY_COUNT=$(python3 -c "import json; print(len(json.load(open('${HISTORY}'))))")
if [[ "${ENTRY_COUNT}" == "0" ]]; then
    log "No images in history to verify, skipping."
    exit 0
fi

# Extract expected digests and build metadata from image-history.json
read -r EXPECTED_TK SOURCE_COMMIT_TK SOURCE_EPOCH_TK < <(python3 -c "
import json
history = json.load(open('${HISTORY}'))
for e in reversed(history):
    if '/tee-k' in e['package']:
        print(e['version'], e.get('sourceCommit',''), e.get('sourceDateEpoch',''))
        break
")

read -r EXPECTED_TT SOURCE_COMMIT_TT SOURCE_EPOCH_TT < <(python3 -c "
import json
history = json.load(open('${HISTORY}'))
for e in reversed(history):
    if '/tee-t' in e['package']:
        print(e['version'], e.get('sourceCommit',''), e.get('sourceDateEpoch',''))
        break
")

if [[ -z "${EXPECTED_TK}" || -z "${EXPECTED_TT}" ]]; then
    echo "ERROR: Could not extract expected digests from ${HISTORY}"
    exit 1
fi

# Validate both services were built with the same epoch
if [[ -n "${SOURCE_EPOCH_TK}" && -n "${SOURCE_EPOCH_TT}" && "${SOURCE_EPOCH_TK}" != "${SOURCE_EPOCH_TT}" ]]; then
    log "ERROR: TEE-K and TEE-T were built with different SOURCE_DATE_EPOCH values"
    exit 1
fi

# Determine SOURCE_DATE_EPOCH from history
EPOCH="${SOURCE_EPOCH_TK:-${SOURCE_EPOCH_TT}}"
if [[ -n "${EPOCH}" ]]; then
    export SOURCE_DATE_EPOCH="${EPOCH}"
    log "Using SOURCE_DATE_EPOCH from image-history.json: ${SOURCE_DATE_EPOCH}"
else
    export SOURCE_DATE_EPOCH=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct)
    log "WARNING: No sourceDateEpoch in history, using git HEAD: ${SOURCE_DATE_EPOCH}"
fi

# Check commit
BUILD_COMMIT="${SOURCE_COMMIT_TK:-${SOURCE_COMMIT_TT}}"
if [[ -n "${BUILD_COMMIT}" ]]; then
    CURRENT_COMMIT=$(git -C "${REPO_ROOT}" rev-parse HEAD)
    if [[ "${CURRENT_COMMIT}" != "${BUILD_COMMIT}" ]]; then
        log "WARNING: Current commit ${CURRENT_COMMIT:0:12} differs from build commit ${BUILD_COMMIT:0:12}"
        log "Verification may fail if source code changed between commits"
    fi
fi

# Create/reuse pinned builder (same image as build.sh)
BUILDER_NAME="reclaim-repro"
if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    log "Creating pinned builder: ${BUILDER_NAME}"
    docker buildx create --name "${BUILDER_NAME}" --driver docker-container \
        --driver-opt image="${BUILDKIT_IMAGE}" --bootstrap
fi
BUILDER_FLAG="--builder=${BUILDER_NAME}"

log "Expected digests from image-history.json:"
log "  TEE-K: ${EXPECTED_TK}"
log "  TEE-T: ${EXPECTED_TT}"

# Build TEE-K
log "Building TEE-K from source..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    -f "${REPO_ROOT}/tee_k/Dockerfile.enclave" \
    -o type=oci,dest="${TMPDIR}/tee-k.tar",rewrite-timestamp=true \
    "${REPO_ROOT}"

# Build TEE-T
log "Building TEE-T from source..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    -f "${REPO_ROOT}/tee_t/Dockerfile.enclave" \
    -o type=oci,dest="${TMPDIR}/tee-t.tar",rewrite-timestamp=true \
    "${REPO_ROOT}"

# Extract digests
extract_digest() {
    local tarball="$1"
    local dir="${tarball%.tar}-oci"
    mkdir -p "${dir}"
    tar -xf "${tarball}" -C "${dir}"
    python3 -c "import json; print(json.load(open('${dir}/index.json'))['manifests'][0]['digest'])"
}

ACTUAL_TK=$(extract_digest "${TMPDIR}/tee-k.tar")
ACTUAL_TT=$(extract_digest "${TMPDIR}/tee-t.tar")

# Compare
PASS=true

echo ""
echo "============================================="
echo "Verification Results:"
echo "============================================="

echo "TEE-K:"
echo "  Expected: ${EXPECTED_TK}"
echo "  Actual:   ${ACTUAL_TK}"
if [[ "${EXPECTED_TK}" == "${ACTUAL_TK}" ]]; then
    echo "  Result:   MATCH"
else
    echo "  Result:   MISMATCH"
    PASS=false
fi

echo ""
echo "TEE-T:"
echo "  Expected: ${EXPECTED_TT}"
echo "  Actual:   ${ACTUAL_TT}"
if [[ "${EXPECTED_TT}" == "${ACTUAL_TT}" ]]; then
    echo "  Result:   MATCH"
else
    echo "  Result:   MISMATCH"
    PASS=false
fi

echo "============================================="

if [[ "${PASS}" == "true" ]]; then
    echo "VERIFICATION PASSED: Images match source code"
    exit 0
else
    echo "VERIFICATION FAILED: Images do not match source code"
    exit 1
fi
