#!/bin/bash
set -euo pipefail

# Build a SEV-SNP TEE image for one role x cloud and package it as a GCP image
# or AWS AMI, ready for snp-pair.sh. One script for the whole pipeline:
# compile (loader + tee binary) -> two-tier image in Docker (snp-image/tier-
# build.sh) -> snp-tier.raw -> cloud image. The app-bundle sha256 IS the
# cross-cloud snp-app: digest (printed at the end).
#
#   ./deploy/snp-build.sh <k|t> <gcp|aws> [TAG]   default TAG = tee<role>-<cloud>
#   ./deploy/snp-build.sh clean
#
# Run with the proxy SET (the AWS steps need it); go/docker/gcloud/gsutil steps
# unset it themselves. Deployment-specific values come from deploy/.env.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
source "${SCRIPT_DIR}/_lib.sh"
set -a; source "${SCRIPT_DIR}/snp-image/pins.env"; set +a

GCP_PROJECT="${GCP_PROJECT:?set GCP_PROJECT in deploy/.env}"
IMG_DIR="${SCRIPT_DIR}/snp-image"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RAW="${IMG_DIR}/snp-tier.raw"
BUNDLE_HOST="${IMG_DIR}/app-bundle.tar"
DOCKER="${DOCKER:-docker}"
AWS_TYPE="${AWS_SNP_TYPE:-c6a.large}"

# The AWS steps go through a flaky local proxy; let the CLI retry dropped
# connections itself so one blip doesn't kill a 10-min VM-import build.
export AWS_MAX_ATTEMPTS="${AWS_MAX_ATTEMPTS:-10}" AWS_RETRY_MODE="${AWS_RETRY_MODE:-standard}"

# Per-cloud kernel + modules; versions pinned in snp-image/pins.env.
kernel_for() { [[ "$1" == aws ]] && echo "${SNP_AWS_KERNEL_PKG}" || echo "${SNP_GCP_KERNEL_PKG}"; }
modules_for() { [[ "$1" == aws ]] && echo "tsm_report sev-guest" || echo "gve"; }

_np() { unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true; }
g() { ( _np; gcloud_retry gcloud "$@" --project="${GCP_PROJECT}" ); }

build_loader() {
    local dst="${IMG_DIR}/mkosi.extra/usr/local/bin/snp-loader"
    echo "[build] compiling loader (stable base init)..."
    mkdir -p "$(dirname "${dst}")"
    # -buildvcs=false: the loader (and thus the base UKI / PCR 11) must NOT embed
    # the repo commit, so the base is reproducible regardless of commit.
    ( _np; cd "${IMG_DIR}/loader" && GOTOOLCHAIN="${SNP_GO_TOOLCHAIN}" GOFLAGS=-mod=readonly GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -buildvcs=false -ldflags "-buildid=" -o "${dst}" . )
    chmod 0755 "${dst}"
    echo "[build] loader sha256: $(sha256sum "${dst}" | cut -d' ' -f1)"
}

# build_bundle compiles tee_<role> + stages mpcl circuits + CA certs into the
# deterministic app bundle (its sha256 is the cross-cloud snp-app: digest).
build_bundle() {
    local role="$1"
    local dst="${IMG_DIR}/mkosi.extra/usr/local/bin/snp-tee${role}"
    echo "[build] compiling tee_${role}..."
    mkdir -p "$(dirname "${dst}")"
    ( _np; cd "${REPO_ROOT}" && GOTOOLCHAIN="${SNP_GO_TOOLCHAIN}" GOFLAGS=-mod=readonly GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -tags 'enclave osusergo netgo static_build' \
        -ldflags "-s -w -buildid= -extldflags=-static" -o "${dst}" "./tee_${role}" )
    chmod 0755 "${dst}"
    local stage; stage="$(mktemp -d)"
    cp "${dst}" "${stage}/app"
    local mpcdir; mpcdir="$( _np; cd "${REPO_ROOT}" && GOTOOLCHAIN="${SNP_GO_TOOLCHAIN}" GOFLAGS=-mod=readonly go list -m -f '{{.Dir}}' github.com/markkurossi/mpc )"
    mkdir -p "${stage}/mpcl"; cp -r "${mpcdir}/pkg" "${stage}/mpcl/pkg"
    mkdir -p "${stage}/etc/ssl/certs"
    ${DOCKER} run --rm "${SNP_CA_IMAGE}" cat /etc/ssl/certs/ca-certificates.crt > "${stage}/etc/ssl/certs/ca-certificates.crt"
    # mpcl is copied from Go's read-only module cache (0444/0555), whose perms
    # vary by host and block the rm below. Canonicalize modes so the tar (-> app
    # digest) is reproducible cross-host AND the staging dir is removable.
    find "${stage}" -type d -exec chmod 0755 {} +
    find "${stage}" -type f -exec chmod 0644 {} +
    chmod 0755 "${stage}/app"
    tar --sort=name --format=gnu --mtime="@1735689600" --owner=0 --group=0 --numeric-owner -C "${stage}" -cf "${BUNDLE_HOST}" .
    rm -rf "${stage}"
    echo "[build] app bundle: $(du -h "${BUNDLE_HOST}" | cut -f1)  sha256: $(sha256sum "${BUNDLE_HOST}" | cut -d' ' -f1)"
}

build_raw() {
    local cloud="$1"
    local img="snp-img-builder-${cloud}"
    echo "[build] two-tier image in Docker (cloud=${cloud} kernel=$(kernel_for "$cloud"))..."
    # Identity-only (verify) builds skip systemd-repart -> no --privileged, no /dev.
    local priv="--privileged -v /dev:/dev" idonly=""
    [[ "${SNP_BUILD_ONLY:-0}" == 1 ]] && { priv=""; idonly="-e SNP_IDENTITY_ONLY=1"; }
    ( _np; ${DOCKER} build --build-arg KERNEL_PKG="$(kernel_for "$cloud")" \
        --build-arg UBUNTU_DIGEST="${SNP_UBUNTU_DIGEST}" \
        --build-arg SYSTEMD_BOOT_VER="${SNP_SYSTEMD_BOOT_VER}" --build-arg SYSTEMD_UKIFY_VER="${SNP_SYSTEMD_UKIFY_VER}" \
        --build-arg SYSTEMD_VER="${SNP_SYSTEMD_VER}" --build-arg ZSTD_VER="${SNP_ZSTD_VER}" \
        --build-arg CPIO_VER="${SNP_CPIO_VER}" --build-arg BINUTILS_VER="${SNP_BINUTILS_VER}" \
        --build-arg http_proxy= --build-arg https_proxy= --build-arg HTTP_PROXY= --build-arg HTTPS_PROXY= --build-arg no_proxy= \
        -t "${img}" "${IMG_DIR}"
      ${DOCKER} run --rm ${priv} \
        -e http_proxy= -e https_proxy= -e HTTP_PROXY= -e HTTPS_PROXY= \
        -e APP_BIN=/work/app-bundle.tar -e MODULES="$(modules_for "$cloud")" -e SNP_CMDLINE="${SNP_CMDLINE:-}" \
        -e SNP_PCR_BANK="$([[ "${cloud}" == aws ]] && echo sha384 || echo sha256)" ${idonly} \
        -v "${IMG_DIR}:/work" "${img}" bash /work/tier-build.sh )
}

package_gcp() {
    local tag="$1"
    local image="snp-${tag}" bucket="gs://${GCP_PROJECT}-snp-images"
    local tmp; tmp="$(mktemp -d)"
    cp --reflink=auto "${RAW}" "${tmp}/disk.raw"
    tar --format=oldgnu -C "${tmp}" -Sczf "${tmp}/${image}.tar.gz" disk.raw
    g storage buckets create "${bucket}" --location=US >/dev/null 2>&1 || true
    echo "[image] uploading ${image}.tar.gz..."
    ( _np; gsutil -q cp "${tmp}/${image}.tar.gz" "${bucket}/${image}.tar.gz" )
    g compute images delete "${image}" --quiet >/dev/null 2>&1 || true
    g compute images create "${image}" --source-uri="${bucket}/${image}.tar.gz" \
        --guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,VIRTIO_SCSI_MULTIQUEUE
    rm -rf "${tmp}"
    echo "[image] GCP image ${image} created -> snp-pair.sh SNP_K_IMAGE/SNP_T_IMAGE=${image}"
}

package_aws() {
    local tag="$1"
    local image="snp-${tag}" region="${AWS_SNP_REGION:?set AWS_SNP_REGION in deploy/.env}"
    local acct bucket key tmp vmdk
    acct="$(aws sts get-caller-identity --query Account --output text)"
    bucket="${SNP_S3_BUCKET:-snp-vmimport-${acct}}"; key="${image}.vmdk"
    tmp="$(mktemp -d)"; vmdk="${tmp}/disk.vmdk"
    echo "[image] raw -> deterministic streamOptimized VMDK..."
    qemu-img convert -f raw -O vmdk -o subformat=streamOptimized "${RAW}" "${vmdk}"
    python3 - "${vmdk}" <<'PY'
import re,sys
p=sys.argv[1]; b=bytearray(open(p,'rb').read())
m=re.search(rb'CID=[0-9a-f]{8}', b); b[m.start():m.end()]=b'CID=00000001'
open(p,'wb').write(b)
PY
    echo "[image] uploading s3://${bucket}/${key}..."
    aws s3 cp "${vmdk}" "s3://${bucket}/${key}" --no-progress; rm -rf "${tmp}"
    local task; task="$(aws --region "${region}" ec2 import-snapshot --description "${image}" \
        --disk-container "Format=VMDK,UserBucket={S3Bucket=${bucket},S3Key=${key}}" --query 'ImportTaskId' --output text)"
    echo "[image] import-snapshot ${task}; waiting (5-15 min)..."
    local snap="" status
    for i in $(seq 1 90); do
        status="$(aws --region "${region}" ec2 describe-import-snapshot-tasks --import-task-ids "${task}" --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.Status' --output text 2>/dev/null || true)"
        echo "  [${i}] status=${status}"
        case "${status}" in
            completed) snap="$(aws --region "${region}" ec2 describe-import-snapshot-tasks --import-task-ids "${task}" --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.SnapshotId' --output text)"; break ;;
            deleted|deleting) echo "[image] import failed" >&2; exit 1 ;;
        esac
        sleep 20
    done
    [[ -n "${snap}" && "${snap}" != None ]] || { echo "[image] no snapshot produced" >&2; exit 1; }
    aws --region "${region}" ec2 deregister-image --image-id "$(aws --region "${region}" ec2 describe-images --owners self --filters "Name=name,Values=${image}" --query 'Images[-1].ImageId' --output text 2>/dev/null)" >/dev/null 2>&1 || true
    local ami; ami="$(aws --region "${region}" ec2 register-image --name "${image}" \
        --architecture x86_64 --virtualization-type hvm --boot-mode uefi --ena-support --sriov-net-support simple \
        --tpm-support v2.0 --root-device-name /dev/xvda \
        --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=${snap},DeleteOnTermination=true,VolumeType=gp3}" \
        --query 'ImageId' --output text)"
    echo "[image] AMI ${ami} (${image}) registered -> snp-pair.sh SNP_T_IMAGE/SNP_K_IMAGE tag = ${tag}"
}

if [[ "${1:-}" == clean ]]; then
    rm -rf "${IMG_DIR}"/*.raw "${BUNDLE_HOST}" "${IMG_DIR}/mkosi.extra/usr/local/bin" 2>/dev/null \
        || sudo rm -rf "${IMG_DIR}"/*.raw "${BUNDLE_HOST}" "${IMG_DIR}/mkosi.extra/usr/local/bin"
    echo "[clean] done"; exit 0
fi

ROLE="${1:?usage: $0 <k|t> <gcp|aws> [TAG]}"
CLOUD="${2:?usage: $0 <k|t> <gcp|aws> [TAG]}"
case "${ROLE}" in k|t) ;; *) echo "role must be k|t" >&2; exit 1 ;; esac
case "${CLOUD}" in gcp|aws) ;; *) echo "cloud must be gcp|aws" >&2; exit 1 ;; esac
TAG="${3:-tee${ROLE}-${CLOUD}}"

# The app digest is VCS-stamped (tracks the commit), so a dirty tree yields a
# vcs.modified artifact, not the clean-commit value. Refuse unless overridden.
if [[ -n "$(git -C "${REPO_ROOT}" status --porcelain 2>/dev/null)" && "${SNP_ALLOW_DIRTY:-0}" != 1 ]]; then
    echo "[build] working tree is dirty -> app digest would be a vcs.modified artifact." >&2
    echo "[build] commit/stash first, or set SNP_ALLOW_DIRTY=1 to override." >&2
    exit 1
fi

echo "[build] === tee_${ROLE}@${CLOUD} (tag ${TAG}) ==="
build_loader
build_bundle "${ROLE}"
build_raw "${CLOUD}"

# Base UKI (PCR 11) is commit-independent -> assert it matches the pin so any
# unexpected base drift (kernel/loader/systemd/cmdline) fails the build loudly.
BASE_UKI="$(sha256sum "${IMG_DIR}/snp-base.efi" | cut -d' ' -f1)"
BASE_VAR="SNP_BASE_UKI_${CLOUD^^}"
if [[ -n "${!BASE_VAR}" && "${!BASE_VAR}" != "${BASE_UKI}" ]]; then
    echo "[build] BASE UKI DRIFT: built ${BASE_UKI}, pins.env ${BASE_VAR}=${!BASE_VAR}" >&2
    echo "[build] the base changed unexpectedly; investigate or bump ${BASE_VAR} in deploy/snp-image/pins.env." >&2
    exit 1
fi

# App bundle (PCR 8) tracks the commit -> compute + report; operator allowlists.
DIGEST="snp-app:$(sha256sum "${BUNDLE_HOST}" | cut -d' ' -f1)"
# SNP_BUILD_ONLY: identity verify (verify.sh) — emit digests, skip cloud packaging.
if [[ "${SNP_BUILD_ONLY:-0}" != 1 ]]; then
    [[ "${CLOUD}" == gcp ]] && package_gcp "${TAG}" || package_aws "${TAG}"
fi
echo "[build] DONE tee_${ROLE}@${CLOUD}"
echo "[build]   base UKI   = ${BASE_UKI}  (${BASE_VAR}, commit-independent)"
echo "[build]   app digest = ${DIGEST}  (commit $(git -C "${REPO_ROOT}" rev-parse --short HEAD))"
echo "[build]   -> record in deploy/image-history.json + allowlist on the router; pass to snp-pair.sh via SNP_${ROLE^^}_DIGEST"
