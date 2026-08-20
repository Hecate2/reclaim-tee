#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_DIR}"' EXIT

OLD_GO="sha256:$(printf '1%.0s' {1..64})"
NEW_GO="sha256:$(printf '2%.0s' {1..64})"
OLD_BK="sha256:$(printf '3%.0s' {1..64})"
NEW_BK="sha256:$(printf '4%.0s' {1..64})"
MOCK_BIN="${TEST_DIR}/bin"
mkdir -p "${MOCK_BIN}"

cat >"${MOCK_BIN}/docker" <<'MOCK'
#!/bin/bash
set -euo pipefail
command="${1:?}"
shift
case "${command}" in
    pull)
        exit 0
        ;;
    manifest)
        case "${MOCK_MODE:-success}" in
            missing-go) printf '%s\n' '{"manifests":[]}' ;;
            malformed-go) printf '%s\n' '{"manifests":[{"platform":{"architecture":"amd64","os":"linux"},"digest":"sha256:abcd"}]}' ;;
            *) printf '{"manifests":[{"platform":{"architecture":"amd64","os":"linux"},"digest":"%s"}]}\n' "${MOCK_NEW_GO}" ;;
        esac
        ;;
    inspect)
        case "$*" in
            *golang*)
                if [[ "${MOCK_MODE:-success}" == version-mismatch ]]; then
                    echo 'GOLANG_VERSION=1.26.7'
                else
                    echo 'GOLANG_VERSION=1.27.0'
                fi
                ;;
            *moby/buildkit*)
                case "${MOCK_MODE:-success}" in
                    malformed-buildkit) echo 'moby/buildkit:buildx-stable-1@sha256:abcd' ;;
                    missing-buildkit) echo 'moby/buildkit:buildx-stable-1@' ;;
                    *) echo "moby/buildkit:buildx-stable-1@${MOCK_NEW_BK}" ;;
                esac
                ;;
            *) exit 1 ;;
        esac
        ;;
    run)
        echo 'buildkitd github.com/moby/buildkit v-test'
        ;;
    *)
        echo "unexpected docker command: ${command}" >&2
        exit 1
        ;;
esac
MOCK
chmod 0755 "${MOCK_BIN}/docker"

make_repo() {
    local repo="$1" go_digest="${2:-${OLD_GO}}"
    mkdir -p "${repo}/deploy/snp-image/loader" "${repo}/tee_k" "${repo}/tee_t" "${repo}/router"
    cp "${SCRIPT_DIR}/update-pins.sh" "${repo}/deploy/update-pins.sh"
    printf 'BUILDKIT_IMAGE="moby/buildkit:buildx-stable-1@%s"\n' "${OLD_BK}" >"${repo}/deploy/build.sh"
    printf 'BUILDKIT_IMAGE="moby/buildkit:buildx-stable-1@%s"\n' "${OLD_BK}" >"${repo}/deploy/verify.sh"
    printf '# Go 1.27.0 -- update digest when upgrading Go\nFROM golang:1.27.0-alpine3.24@%s AS app-builder\n' "${go_digest}" >"${repo}/tee_k/Dockerfile.enclave"
    cp "${repo}/tee_k/Dockerfile.enclave" "${repo}/tee_t/Dockerfile.enclave"
    printf '# Go 1.27.0 -- keep this digest in sync\nFROM golang:1.27.0-alpine3.24@%s AS app-builder\n' "${go_digest}" >"${repo}/router/Dockerfile"
    printf '%s\n' 'loader-must-not-change' >"${repo}/deploy/snp-image/loader/main.go"
}

snapshot() {
    local repo="$1"
    find "${repo}" -type f -print0 | sort -z | xargs -0 sha256sum
}

assert_failed_atomically() {
    local name="$1" mode="$2" initial_go="${3:-${OLD_GO}}" repo before after
    repo="${TEST_DIR}/${name}"
    make_repo "${repo}" "${initial_go}"
    before="$(snapshot "${repo}")"
    if PATH="${MOCK_BIN}:${PATH}" MOCK_MODE="${mode}" MOCK_NEW_GO="${NEW_GO}" MOCK_NEW_BK="${NEW_BK}" \
        bash "${repo}/deploy/update-pins.sh" --update >"${TEST_DIR}/${name}.log" 2>&1; then
        echo "update-pins accepted invalid case: ${name}" >&2
        exit 1
    fi
    after="$(snapshot "${repo}")"
    [[ "${before}" == "${after}" ]] || {
        echo "update-pins modified files after failed case: ${name}" >&2
        exit 1
    }
}

assert_failed_atomically malformed-current success sha256:abcd
assert_failed_atomically missing-go missing-go
assert_failed_atomically malformed-go malformed-go
assert_failed_atomically version-mismatch version-mismatch
assert_failed_atomically malformed-buildkit malformed-buildkit
assert_failed_atomically missing-buildkit missing-buildkit

SUCCESS_REPO="${TEST_DIR}/success"
make_repo "${SUCCESS_REPO}"
LOADER_BEFORE="$(sha256sum "${SUCCESS_REPO}/deploy/snp-image/loader/main.go")"
PATH="${MOCK_BIN}:${PATH}" MOCK_MODE=success MOCK_NEW_GO="${NEW_GO}" MOCK_NEW_BK="${NEW_BK}" \
    bash "${SUCCESS_REPO}/deploy/update-pins.sh" --update >"${TEST_DIR}/success.log"
for dockerfile in tee_k/Dockerfile.enclave tee_t/Dockerfile.enclave router/Dockerfile; do
    grep -Fqx "FROM golang:1.27.0-alpine3.24@${NEW_GO} AS app-builder" "${SUCCESS_REPO}/${dockerfile}"
done
grep -Fq "@${NEW_BK}\"" "${SUCCESS_REPO}/deploy/build.sh"
grep -Fq "@${NEW_BK}\"" "${SUCCESS_REPO}/deploy/verify.sh"
[[ "$(sha256sum "${SUCCESS_REPO}/deploy/snp-image/loader/main.go")" == "${LOADER_BEFORE}" ]]

echo "update-pins validation and atomicity tests passed"
