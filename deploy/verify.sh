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
BUILDKIT_IMAGE="moby/buildkit:buildx-stable-1@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"

TMPDIR=$(mktemp -d)
WORKTREE_DIR=""
cleanup() {
    if [[ -n "${WORKTREE_DIR}" && -d "${WORKTREE_DIR}" ]]; then
        git -C "${REPO_ROOT}" worktree remove --force "${WORKTREE_DIR}" 2>/dev/null || true
    fi
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

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

# Require both services to reference the same source commit.
if [[ -n "${SOURCE_COMMIT_TK}" && -n "${SOURCE_COMMIT_TT}" && "${SOURCE_COMMIT_TK}" != "${SOURCE_COMMIT_TT}" ]]; then
    log "ERROR: TEE-K and TEE-T have different sourceCommit values"
    exit 1
fi

BUILD_COMMIT="${SOURCE_COMMIT_TK:-${SOURCE_COMMIT_TT}}"
if [[ -z "${BUILD_COMMIT}" ]]; then
    log "ERROR: image-history.json entry has no sourceCommit -- cannot verify reproducibility"
    exit 1
fi

if ! git -C "${REPO_ROOT}" rev-parse --verify "${BUILD_COMMIT}^{commit}" >/dev/null 2>&1; then
    log "ERROR: sourceCommit ${BUILD_COMMIT} not found in repository"
    exit 1
fi

# Determine SOURCE_DATE_EPOCH from history (preferred) or the recorded commit's time.
EPOCH="${SOURCE_EPOCH_TK:-${SOURCE_EPOCH_TT}}"
if [[ -n "${EPOCH}" ]]; then
    export SOURCE_DATE_EPOCH="${EPOCH}"
    log "Using SOURCE_DATE_EPOCH from image-history.json: ${SOURCE_DATE_EPOCH}"
else
    export SOURCE_DATE_EPOCH=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct "${BUILD_COMMIT}")
    log "WARNING: No sourceDateEpoch in history, using commit time: ${SOURCE_DATE_EPOCH}"
fi

log "Verifying recorded build commit: ${BUILD_COMMIT:0:12}"

# Verify against the commit the image was released from, not HEAD. The property
# being checked is "the recorded image is reproducible from its recorded source
# commit" -- which is independent of what's happening on the current branch.
WORKTREE_DIR="${TMPDIR}/src"
git -C "${REPO_ROOT}" worktree add --detach "${WORKTREE_DIR}" "${BUILD_COMMIT}" >/dev/null

# Normalize file mtimes to SOURCE_DATE_EPOCH. rewrite-timestamp only clamps
# timestamps NEWER than the epoch, so older mtimes from different checkouts
# would otherwise produce different layers.
find "${WORKTREE_DIR}" -not -path '*/.git/*' -exec touch -d "@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null || true

# Create/reuse pinned builder (same image as build.sh)
BUILDER_NAME="reclaim-repro"
if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    log "Creating pinned builder: ${BUILDER_NAME}"
    docker buildx create --name "${BUILDER_NAME}" --driver docker-container \
        --driver-opt image="${BUILDKIT_IMAGE}" \
        --bootstrap
fi
BUILDER_FLAG="--builder=${BUILDER_NAME}"

log "Expected digests from image-history.json:"
log "  TEE-K: ${EXPECTED_TK}"
log "  TEE-T: ${EXPECTED_TT}"

# Build TEE-K
log "Building TEE-K from source..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    -f "${WORKTREE_DIR}/tee_k/Dockerfile.enclave" \
    -o type=oci,dest="${TMPDIR}/tee-k.tar",rewrite-timestamp=true \
    "${WORKTREE_DIR}"

# Build TEE-T
log "Building TEE-T from source..."
docker buildx build ${BUILDER_FLAG} --no-cache \
    -f "${WORKTREE_DIR}/tee_t/Dockerfile.enclave" \
    -o type=oci,dest="${TMPDIR}/tee-t.tar",rewrite-timestamp=true \
    "${WORKTREE_DIR}"

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

    # Dump debug info: compare OCI manifests and layer hashes
    echo ""
    echo "=== DEBUG: TEE-K OCI manifest ==="
    cat "${TMPDIR}/tee-k-oci/index.json" 2>/dev/null | python3 -m json.tool || true

    echo ""
    echo "=== DEBUG: TEE-K config ==="
    MANIFEST_DIGEST=$(python3 -c "import json; print(json.load(open('${TMPDIR}/tee-k-oci/index.json'))['manifests'][0]['digest'].split(':')[1])" 2>/dev/null)
    if [[ -n "${MANIFEST_DIGEST}" ]]; then
        cat "${TMPDIR}/tee-k-oci/blobs/sha256/${MANIFEST_DIGEST}" 2>/dev/null | python3 -m json.tool || true
    fi

    echo ""
    echo "=== DEBUG: TEE-K layer listing ==="
    find "${TMPDIR}/tee-k-oci/blobs" -type f -exec sha256sum {} \; 2>/dev/null | sort || true

    echo ""
    echo "=== DEBUG: BuildKit worker info ==="
    docker exec buildx_buildkit_reclaim-repro0 cat /proc/1/cmdline 2>/dev/null | tr '\0' ' ' || true
    echo ""

    # Save tarballs for artifact upload
    mkdir -p /tmp/verify-debug
    cp "${TMPDIR}"/tee-*.tar /tmp/verify-debug/ 2>/dev/null || true

    exit 1
fi
