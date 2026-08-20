#!/bin/bash
set -euo pipefail

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
GOLANG_TAG="golang:1.27.0-alpine3.24"
EXPECTED_GO_VERSION="1.27.0"
BUILDKIT_TAG="moby/buildkit:buildx-stable-1"

require_digest() {
    local name="$1" digest="$2"
    [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        echo "ERROR: ${name} is not an exact lowercase sha256 digest" >&2
        return 1
    }
}

go_digest_from() {
    local dockerfile="$1"
    sed -n "s|^FROM ${GOLANG_TAG}@\\(sha256:[0-9a-f]*\\) AS app-builder$|\\1|p" "${dockerfile}"
}

current_go_digest() {
    local tee_k tee_t router
    tee_k="$(go_digest_from "${REPO_ROOT}/tee_k/Dockerfile.enclave")"
    tee_t="$(go_digest_from "${REPO_ROOT}/tee_t/Dockerfile.enclave")"
    router="$(go_digest_from "${REPO_ROOT}/router/Dockerfile")"
    require_digest "TEE-K Go digest" "${tee_k}" || return
    require_digest "TEE-T Go digest" "${tee_t}" || return
    require_digest "router Go digest" "${router}" || return
    if [[ "${tee_k}" != "${tee_t}" || "${tee_k}" != "${router}" ]]; then
        echo "ERROR: app-builder Go pins are missing or inconsistent" >&2
        return 1
    fi
    printf '%s\n' "${tee_k}"
}

buildkit_digest_from() {
    local script="$1"
    sed -n 's|^BUILDKIT_IMAGE="moby/buildkit:buildx-stable-1@\(sha256:[0-9a-f]*\)"$|\1|p' "${script}"
}

current_buildkit_digest() {
    local build verify
    build="$(buildkit_digest_from "${REPO_ROOT}/deploy/build.sh")"
    verify="$(buildkit_digest_from "${REPO_ROOT}/deploy/verify.sh")"
    require_digest "build.sh BuildKit digest" "${build}" || return
    require_digest "verify.sh BuildKit digest" "${verify}" || return
    [[ "${build}" == "${verify}" ]] || {
        echo "ERROR: BuildKit pins are inconsistent" >&2
        return 1
    }
    printf '%s\n' "${build}"
}

show_current() {
    echo "=== Current Pinned Versions ==="
    echo ""

    CURRENT_GO="$(current_go_digest)"
    CURRENT_BK="$(current_buildkit_digest)"

    echo "Go/Alpine base image:"
    echo "  Digest: ${CURRENT_GO}"
    docker pull --quiet "${GOLANG_TAG}@${CURRENT_GO}" >/dev/null 2>&1 || true
    GO_VER=$(docker inspect "${GOLANG_TAG}@${CURRENT_GO}" --format='{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep GOLANG_VERSION | cut -d= -f2 || true)
    echo "  Go version: ${GO_VER:-unknown}"
    echo ""

    echo "BuildKit image:"
    echo "  Digest: ${CURRENT_BK}"
    docker pull --quiet "${BUILDKIT_TAG}@${CURRENT_BK}" >/dev/null 2>&1 || true
    BK_VER=$(docker run --rm "${BUILDKIT_TAG}@${CURRENT_BK}" --version 2>/dev/null | awk '{print $3}' || true)
    echo "  BuildKit version: ${BK_VER:-unknown}"
}

update_pins() {
    local OLD_GO OLD_BK NEW_GO NEW_BK GO_VER BK_VER
    echo "=== Pulling Latest Versions ==="
    echo ""

    # Validate every current pin before consulting the registry. No file is
    # modified until all current and replacement values pass exact checks.
    OLD_GO="$(current_go_digest)"
    OLD_BK="$(current_buildkit_digest)"

    # Get latest Go/Alpine amd64 digest.
    # Pull the tag for the local `docker inspect` GOLANG_VERSION lookup below,
    # but read the multi-arch index directly from the registry — depending on
    # Docker's image store, the local RepoDigests[0] may be a per-platform
    # manifest digest, which makes `docker manifest inspect tag@digest` return
    # nothing and crashes the JSON parser.
    echo "Pulling ${GOLANG_TAG}..."
    docker pull --quiet "${GOLANG_TAG}" >/dev/null
    NEW_GO=$(docker manifest inspect "${GOLANG_TAG}" | python3 -c "
import json,sys
data = json.load(sys.stdin)
for m in data.get('manifests', []):
    p = m.get('platform', {})
    if p.get('architecture') == 'amd64' and p.get('os') == 'linux':
        print(m['digest'])
        break
")
    if [[ -z "${NEW_GO}" ]]; then
        echo "ERROR: failed to resolve amd64 digest from 'docker manifest inspect ${GOLANG_TAG}'" >&2
        exit 1
    fi
    require_digest "registry Go digest" "${NEW_GO}"
    GO_VER=$(docker inspect "${GOLANG_TAG}" --format='{{range .Config.Env}}{{println .}}{{end}}' | grep GOLANG_VERSION | cut -d= -f2)
    if [[ "${GO_VER}" != "${EXPECTED_GO_VERSION}" ]]; then
        echo "ERROR: ${GOLANG_TAG} reports Go ${GO_VER:-unknown}, expected ${EXPECTED_GO_VERSION}" >&2
        exit 1
    fi
    echo "  Go ${GO_VER}: ${NEW_GO}"

    # Get latest BuildKit digest
    echo "Pulling ${BUILDKIT_TAG}..."
    docker pull --quiet "${BUILDKIT_TAG}" >/dev/null
    NEW_BK=$(docker inspect "${BUILDKIT_TAG}" --format='{{index .RepoDigests 0}}' | sed 's/.*@//')
    require_digest "registry BuildKit digest" "${NEW_BK}"
    BK_VER=$(docker run --rm "${BUILDKIT_TAG}" --version 2>/dev/null | awk '{print $3}')
    echo "  BuildKit ${BK_VER}: ${NEW_BK}"

    echo ""
    echo "=== Updating Files ==="

    if [[ "${OLD_GO}" == "${NEW_GO}" ]]; then
        echo "Go/Alpine: already up to date"
    else
        echo "Go/Alpine: updating..."
        sed -i "s|${GOLANG_TAG}@${OLD_GO}|${GOLANG_TAG}@${NEW_GO}|g" \
            "${REPO_ROOT}/tee_k/Dockerfile.enclave" \
            "${REPO_ROOT}/tee_t/Dockerfile.enclave" \
            "${REPO_ROOT}/router/Dockerfile"
        sed -i "s|# Go .*-- update|# Go ${GO_VER} -- update|" \
            "${REPO_ROOT}/tee_k/Dockerfile.enclave" \
            "${REPO_ROOT}/tee_t/Dockerfile.enclave"
        sed -i "s|# Go .*-- keep|# Go ${GO_VER} -- keep|" \
            "${REPO_ROOT}/router/Dockerfile"
        echo "  Updated tee_k, tee_t, and router Dockerfiles"
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

    [[ "$(current_go_digest)" == "${NEW_GO}" ]] || {
        echo "ERROR: Go pins did not update consistently" >&2
        exit 1
    }
    [[ "$(current_buildkit_digest)" == "${NEW_BK}" ]] || {
        echo "ERROR: BuildKit pins did not update consistently" >&2
        exit 1
    }

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
