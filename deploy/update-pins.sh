#!/bin/bash
set -e

# =============================================================================
# Update pinned image digests in Dockerfiles and build scripts.
# Run this when upgrading Go, Alpine, or BuildKit versions.
#
# Usage:
#   ./update-pins.sh              # show current pins
#   ./update-pins.sh --update     # pull latest and update all pins
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"

# Current pins
GOLANG_TAG="golang:alpine"
BUILDKIT_TAG="moby/buildkit:buildx-stable-1"

show_current() {
    echo "=== Current Pinned Versions ==="
    echo ""

    CURRENT_GO=$(grep 'FROM golang:alpine@' "${REPO_ROOT}/tee_k/Dockerfile.enclave" | head -1 | sed 's/.*@//' | sed 's/ .*//')
    CURRENT_BK=$(grep 'BUILDKIT_IMAGE=' "${REPO_ROOT}/deploy/build.sh" | head -1 | sed 's/.*@//' | sed 's/".*//')

    echo "Go/Alpine base image:"
    echo "  Digest: ${CURRENT_GO}"
    docker pull --quiet "${GOLANG_TAG}@${CURRENT_GO}" >/dev/null 2>&1 || true
    GO_VER=$(docker inspect "${GOLANG_TAG}@${CURRENT_GO}" --format='{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep GOLANG_VERSION | cut -d= -f2)
    echo "  Go version: ${GO_VER:-unknown}"
    echo ""

    echo "BuildKit image:"
    echo "  Digest: ${CURRENT_BK}"
    docker pull --quiet "${BUILDKIT_TAG}@${CURRENT_BK}" >/dev/null 2>&1 || true
    BK_VER=$(docker run --rm "${BUILDKIT_TAG}@${CURRENT_BK}" --version 2>/dev/null | awk '{print $3}' || echo "unknown")
    echo "  BuildKit version: ${BK_VER}"
}

update_pins() {
    echo "=== Pulling Latest Versions ==="
    echo ""

    # Get latest Go/Alpine amd64 digest
    echo "Pulling ${GOLANG_TAG}..."
    docker pull --quiet "${GOLANG_TAG}" >/dev/null
    MULTI_DIGEST=$(docker inspect "${GOLANG_TAG}" --format='{{index .RepoDigests 0}}' | sed 's/.*@//')
    # Get amd64-specific manifest
    NEW_GO=$(docker manifest inspect "${GOLANG_TAG}@${MULTI_DIGEST}" 2>/dev/null | python3 -c "
import json,sys
data = json.load(sys.stdin)
for m in data.get('manifests', []):
    p = m.get('platform', {})
    if p.get('architecture') == 'amd64' and p.get('os') == 'linux':
        print(m['digest'])
        break
")
    GO_VER=$(docker inspect "${GOLANG_TAG}" --format='{{range .Config.Env}}{{println .}}{{end}}' | grep GOLANG_VERSION | cut -d= -f2)
    echo "  Go ${GO_VER}: ${NEW_GO}"

    # Get latest BuildKit digest
    echo "Pulling ${BUILDKIT_TAG}..."
    docker pull --quiet "${BUILDKIT_TAG}" >/dev/null
    NEW_BK=$(docker inspect "${BUILDKIT_TAG}" --format='{{index .RepoDigests 0}}' | sed 's/.*@//')
    BK_VER=$(docker run --rm "${BUILDKIT_TAG}" --version 2>/dev/null | awk '{print $3}')
    echo "  BuildKit ${BK_VER}: ${NEW_BK}"

    echo ""
    echo "=== Updating Files ==="

    # Get current digests
    OLD_GO=$(grep 'FROM golang:alpine@' "${REPO_ROOT}/tee_k/Dockerfile.enclave" | head -1 | sed 's/.*@//' | sed 's/ .*//')
    OLD_BK=$(grep 'BUILDKIT_IMAGE=' "${REPO_ROOT}/deploy/build.sh" | head -1 | sed 's/.*@//' | sed 's/".*//')

    if [[ "${OLD_GO}" == "${NEW_GO}" ]]; then
        echo "Go/Alpine: already up to date"
    else
        echo "Go/Alpine: updating..."
        sed -i "s|golang:alpine@${OLD_GO}|golang:alpine@${NEW_GO}|g" \
            "${REPO_ROOT}/tee_k/Dockerfile.enclave" \
            "${REPO_ROOT}/tee_t/Dockerfile.enclave"
        sed -i "s|# Go .*-- update|# Go ${GO_VER} -- update|" \
            "${REPO_ROOT}/tee_k/Dockerfile.enclave" \
            "${REPO_ROOT}/tee_t/Dockerfile.enclave"
        echo "  Updated Dockerfiles"
    fi

    if [[ "${OLD_BK}" == "${NEW_BK}" ]]; then
        echo "BuildKit: already up to date"
    else
        echo "BuildKit: updating..."
        sed -i "s|${OLD_BK}|${NEW_BK}|g" \
            "${REPO_ROOT}/deploy/build.sh" \
            "${REPO_ROOT}/deploy/verify.sh"
        echo "  Updated build.sh and verify.sh"
    fi

    echo ""
    echo "Done. Run './deploy/build.sh v2 --verify' to test before deploying."
}

case "${1:-}" in
    --update)
        update_pins
        ;;
    *)
        show_current
        echo ""
        echo "Run with --update to pull latest and update pins."
        ;;
esac
