#!/bin/bash
set -euo pipefail

# Bring up / tear down ONE SEV-SNP TEE pair, any cloud per half (default
# K@gcp + T@aws). Each half independently picks a cloud (gcp|aws), a location
# (gcp zone | aws region) and a pre-built image (snp-build.sh).
#
#   ./deploy/snp-pair.sh up | status | down
#   ./deploy/snp-pair.sh reset <k|t>     reboot one half (new pair_id, same IP)
#
# Per-half overrides via env or deploy/.env: SNP_K_CLOUD / SNP_K_LOCATION /
# SNP_K_IMAGE and the SNP_T_* equivalents. A stable IP is allocated per half up
# front (gcp static address, aws EIP) so any cloud combination cross-wires and
# survives a reset. Everything deployment-specific lives in deploy/.env.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
source "${SCRIPT_DIR}/_lib.sh"
# Per-cloud base UKI identities (SNP_BASE_DIGEST_GCP/AWS) for EXPECTED_PEER_BASE_DIGEST.
set -a; source "${SCRIPT_DIR}/snp-image/pins.env"; set +a
EXPECTED_BASE_DIGESTS="$(python3 -c "
import json
items = json.load(open('${SCRIPT_DIR}/image-history.json')).get('base_images', [])
print(','.join(dict.fromkeys(x['base'] for x in items)))
")"
[[ -n "${EXPECTED_BASE_DIGESTS}" ]] || {
    echo "deploy/image-history.json contains no SNP base identities" >&2
    exit 1
}

GCP_PROJECT="${GCP_PROJECT:?set GCP_PROJECT in deploy/.env}"
PAIR_NAME="${SNP_PAIR_NAME:-snp-pair}"
# SNP_TARGET selects the router the pair registers with + the JWT issuer/pubkey
# it trusts. test = SNP test router (local signing key, derived below). prod =
# the production router (KMS-signed; pubkey fetched from its /jwt-pubkey).
TARGET="${SNP_TARGET:-test}"
case "${TARGET}" in
test)
	ROUTER_URL="${SNP_ROUTER_URL:?set SNP_ROUTER_URL in deploy/.env}"
	JWT_ISSUER="${SNP_JWT_ISSUER:?set SNP_JWT_ISSUER in deploy/.env}"
	;;
prod)
	ROUTER_URL="${ROUTER_URL:?set ROUTER_URL in deploy/.env}"
	JWT_ISSUER="${ROUTER_JWT_ISSUER:?set ROUTER_JWT_ISSUER in deploy/.env}"
	;;
*)
	echo "SNP_TARGET must be 'test' or 'prod' (got '${TARGET}')" >&2; exit 1 ;;
esac
# Prod defaults to the standard HTTPS port + info logging; test keeps 8081/debug.
# Explicit SNP_PORT / SNP_LOG_LEVEL still override either way.
PORT="${SNP_PORT:-$([[ "${TARGET}" == prod ]] && echo 443 || echo 8081)}"
LOG_LEVEL="${SNP_LOG_LEVEL:-$([[ "${TARGET}" == prod ]] && echo info || echo debug)}"
STATIC_OPRF="${SNP_TEST_STATIC_OPRF:-1}"
AWS_ATTESTATION_V2_REQUIRED="${SNP_AWS_ATTESTATION_V2_REQUIRED:-0}"
AWS_TYPE="${SNP_PAIR_AWS_TYPE:-c6a.large}"
AWS_IAM_PROFILE="${SNP_AWS_IAM_PROFILE:-snp-tee-logger}"
GCP_MACHINE="${SNP_GCP_MACHINE:-n2d-standard-2}"
KEYNAME="${SNP_AWS_KEYNAME:-snp-img-key}"
SIGNKEY="${SCRIPT_DIR}/.test-router-signing-key"

# AWS calls go through a flaky local proxy; let the CLI retry dropped
# connections so a blip can't half-finish an up/down (e.g. terminate K, miss T).
export AWS_MAX_ATTEMPTS="${AWS_MAX_ATTEMPTS:-10}" AWS_RETRY_MODE="${AWS_RETRY_MODE:-standard}"

K_CLOUD="${SNP_K_CLOUD:-gcp}"
T_CLOUD="${SNP_T_CLOUD:-aws}"
default_loc() { [[ "$1" == gcp ]] && echo "${SNP_PAIR_GCP_ZONE:?set SNP_PAIR_GCP_ZONE in deploy/.env}" || echo "${SNP_PAIR_AWS_REGION:?set SNP_PAIR_AWS_REGION in deploy/.env}"; }
default_img() { [[ "$1" == gcp ]] && echo "snp-tee${2}-gcp" || echo "tee${2}-aws"; }
K_LOC="${SNP_K_LOCATION:-$(default_loc "${K_CLOUD}")}"
T_LOC="${SNP_T_LOCATION:-$(default_loc "${T_CLOUD}")}"
K_IMG="${SNP_K_IMAGE:-$(default_img "${K_CLOUD}" k)}"
T_IMG="${SNP_T_IMAGE:-$(default_img "${T_CLOUD}" t)}"
# App digests track the commit (image-history.json), so they're passed per-run,
# not committed: SNP_K_DIGEST / SNP_T_DIGEST from that build's output.
K_DIGEST="${SNP_K_DIGEST:?set SNP_K_DIGEST (tee_k app digest for this build) — see image-history.json / snp-build.sh output}"
T_DIGEST="${SNP_T_DIGEST:?set SNP_T_DIGEST (tee_t app digest for this build)}"
K_DEPLOY_KEY="${TEE_K_DEPLOYMENT_KEY:?set TEE_K_DEPLOYMENT_KEY in deploy/.env}"
T_DEPLOY_KEY="${TEE_T_DEPLOYMENT_KEY:?set TEE_T_DEPLOYMENT_KEY in deploy/.env}"

g() { ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true; gcloud_retry gcloud "$@" --project="${GCP_PROJECT}" ); }
awsr() { local r="$1"; shift; aws --region "$r" "$@"; }
gcp_region() { echo "${1%-*}"; }

jwt_pubkey() {
    if [[ "${TARGET}" == prod ]]; then
        # Prod router signs JWTs with KMS -> no local key; fetch its published
        # pubkey (proxy unset: the router LB is directly reachable). Same PEM
        # shape as the test path, joined to a single \n-escaped metadata value.
        local pem
        pem="$(unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY; curl -fsS "${ROUTER_URL}/jwt-pubkey")" \
            || { echo "failed to fetch ${ROUTER_URL}/jwt-pubkey" >&2; exit 1; }
        printf '%s\n' "${pem}" | awk 'NR>1{printf "\\n"}{printf "%s",$0}'
        return
    fi
    [[ -f "${SIGNKEY}" ]] || { echo "missing ${SIGNKEY} (test router signing key)" >&2; exit 1; }
    printf '%b' "$(cat "${SIGNKEY}")" | openssl ec -pubout 2>/dev/null | awk 'NR>1{printf "\\n"}{printf "%s",$0}'
}
find_ami() { awsr "$1" ec2 describe-images --owners self --filters "Name=name,Values=snp-$2" "Name=state,Values=available" --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text 2>/dev/null; }

ensure_gcp_fw() {
    g compute firewall-rules create "snp-test-allow-${PORT}" --network=default \
        --direction=INGRESS --action=ALLOW --rules="tcp:${PORT}" --source-ranges=0.0.0.0/0 --quiet >/dev/null 2>&1 || true
}
ensure_sg() {
    local region="$1" sg="${PAIR_NAME}-sg" sgid
    sgid="$(awsr "$region" ec2 describe-security-groups --group-names "$sg" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
    [[ -z "$sgid" || "$sgid" == None ]] && sgid="$(awsr "$region" ec2 create-security-group --group-name "$sg" --description "${PAIR_NAME}" --query 'GroupId' --output text)"
    awsr "$region" ec2 authorize-security-group-ingress --group-id "$sgid" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    awsr "$region" ec2 authorize-security-group-ingress --group-id "$sgid" --protocol tcp --port "${PORT}" --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    echo "$sgid"
}

# alloc_ip <role> <cloud> <loc> -> reserves (or reuses) a stable external IP and prints it.
alloc_ip() {
    local role="$1" cloud="$2" loc="$3"
    local name="${PAIR_NAME}-${role}"
    if [[ "$cloud" == gcp ]]; then
        local region; region="$(gcp_region "$loc")"
        g compute addresses create "${name}-ip" --region="$region" >/dev/null 2>&1 || true
        g compute addresses describe "${name}-ip" --region="$region" --format='value(address)'
    else
        local alloc
        alloc="$(awsr "$loc" ec2 describe-addresses --filters "Name=tag:Name,Values=${name}-aws" --query 'Addresses[0].AllocationId' --output text 2>/dev/null || true)"
        if [[ -z "$alloc" || "$alloc" == None ]]; then
            alloc="$(awsr "$loc" ec2 allocate-address --domain vpc --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=${name}-aws}]" --query 'AllocationId' --output text)"
        fi
        awsr "$loc" ec2 describe-addresses --allocation-ids "$alloc" --query 'Addresses[0].PublicIp' --output text
    fi
}

# write_env builds the tee-env / user-data file shared shape + cloud extras.
write_env() {
    local f="$1" cloud="$2" role="$3" loc="$4" self_ip="$5" peer_ip="$6" peer_digest="$7" deploy_key="$8"
    {
        echo "ROUTER_URL=${ROUTER_URL}"
        echo "SELF_ADDR=${self_ip}:${PORT}"
        echo "PEER_ADDR=${peer_ip}:${PORT}"
        echo "EXPECTED_PEER_IMAGE_DIGEST=${peer_digest}"
        # Both clouds' bases; the peer's must match one (no per-side mapping).
        # Keep every recorded base generation during expansion and rollback.
        echo "EXPECTED_PEER_BASE_DIGEST=${EXPECTED_BASE_DIGESTS}"
        echo "SNP_AWS_ATTESTATION_V2_REQUIRED=${AWS_ATTESTATION_V2_REQUIRED}"
        echo "JWT_PUBLIC_KEY=${JWT}"
        echo "EXPECTED_JWT_ISSUER=${JWT_ISSUER}"
        echo "PORT=${PORT}"
        echo "LOG_LEVEL=${LOG_LEVEL}"
        if [[ "${STATIC_OPRF}" == 1 ]]; then
            echo "SNP_TEST_STATIC_OPRF=1"
        else
            echo "KMS_ENCLAVE_DOMAIN_KEY=${deploy_key}"
        fi
        if [[ "$cloud" == gcp ]]; then
            echo "GCP_PROJECT_ID=${GCP_PROJECT}"
            if [[ "${STATIC_OPRF}" != 1 ]]; then
                echo "GOOGLE_PROJECT_ID=${GCP_PROJECT}"
                echo "GOOGLE_KMS_KEYRING=${KMS_KEYRING:?set KMS_KEYRING in deploy/.env}"
                [[ "$role" == k ]] && { echo "GOOGLE_KMS_LOCATION=${TEE_K_KMS_LOCATION:?}"; echo "GOOGLE_KMS_KEY=${TEE_K_KMS_KEY:?}"; } \
                                   || { echo "GOOGLE_KMS_LOCATION=${TEE_T_KMS_LOCATION:?}"; echo "GOOGLE_KMS_KEY=${TEE_T_KMS_KEY:?}"; }
            fi
        else
            echo "CLOUDWATCH_LOG_GROUP=/reclaim-tee/snp"
            echo "AWS_REGION=${loc}"
        fi
    } > "$f"
}

# create_half <role> <cloud> <loc> <img> <self_ip> <peer_ip> <peer_digest> <deploy_key>
create_half() {
    local role="$1" cloud="$2" loc="$3" img="$4" self_ip="$5" peer_ip="$6" peer_digest="$7" deploy_key="$8"
    local envf; envf="$(mktemp)"
    write_env "$envf" "$cloud" "$role" "$loc" "$self_ip" "$peer_ip" "$peer_digest" "$deploy_key"
    if [[ "$cloud" == gcp ]]; then
        local vm="${PAIR_NAME}-${role}-gcp"
        g compute instances describe "$img" >/dev/null 2>&1 || g compute images describe "$img" --format='value(name)' >/dev/null 2>&1 || true
        g compute instances delete "$vm" --zone="$loc" --quiet >/dev/null 2>&1 || true
        # Real OPRF needs Secret Manager + KMS, which the default compute SA's
        # scopes don't grant -> attach the role SA + cloud-platform scope. The
        # static-share path stays SA-less (matches NoopTokenSource registration).
        local sa_flags=()
        if [[ "${STATIC_OPRF}" != 1 ]]; then
            local role_sa; [[ "$role" == k ]] && role_sa="${TEE_K_SA:?set TEE_K_SA in deploy/.env}" || role_sa="${TEE_T_SA:?set TEE_T_SA in deploy/.env}"
            sa_flags=(--service-account="${role_sa}" --scopes=cloud-platform)
        fi
        g compute instances create "$vm" --zone="$loc" --machine-type="${GCP_MACHINE}" \
            --confidential-compute-type=SEV_SNP --min-cpu-platform="AMD Milan" --maintenance-policy=TERMINATE \
            --no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
            "${sa_flags[@]}" \
            --image="$img" --image-project="${GCP_PROJECT}" --address="${self_ip}" \
            --metadata-from-file "tee-env=${envf}" --quiet >/dev/null
    else
        local ami sgid iid; ami="$(find_ami "$loc" "$img")"
        [[ -n "$ami" && "$ami" != None ]] || { echo "no AMI snp-${img} in ${loc}; build it (snp-build.sh ${role} aws)" >&2; rm -f "$envf"; exit 1; }
        sgid="$(ensure_sg "$loc")"
        iid="$(awsr "$loc" ec2 run-instances --image-id "$ami" --instance-type "${AWS_TYPE}" --cpu-options AmdSevSnp=enabled \
            --key-name "${KEYNAME}" --security-group-ids "$sgid" --iam-instance-profile "Name=${AWS_IAM_PROFILE}" \
            --user-data "file://${envf}" --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${PAIR_NAME}-${role}-aws}]" \
            --query 'Instances[0].InstanceId' --output text)"
        awsr "$loc" ec2 wait instance-running --instance-ids "$iid"
        awsr "$loc" ec2 associate-address --instance-id "$iid" --allocation-id "$(awsr "$loc" ec2 describe-addresses --filters "Name=tag:Name,Values=${PAIR_NAME}-${role}-aws" --query 'Addresses[0].AllocationId' --output text)" >/dev/null
    fi
    rm -f "$envf"
}

poll_health() {
    local kip="$1" tip="$2" kok="" tok=""
    for i in $(seq 1 48); do
        [[ -z "$kok" ]] && curl -fksS --max-time 4 "https://${kip}:${PORT}/health" >/dev/null 2>&1 && { kok=1; echo "  [${i}] K ${kip} healthy"; }
        [[ -z "$tok" ]] && curl -fksS --max-time 4 "https://${tip}:${PORT}/health" >/dev/null 2>&1 && { tok=1; echo "  [${i}] T ${tip} healthy"; }
        [[ -n "$kok" && -n "$tok" ]] && { echo "[up] both healthy; pair registers with ${ROUTER_URL} on boot."; return 0; }
        sleep 10
    done
    echo "[up] not both healthy (K=${kok:-no} T=${tok:-no}). Check Cloud Logging / CloudWatch." >&2
}

cmd_up() {
    JWT="$(jwt_pubkey)"
    [[ "$K_CLOUD" == gcp || "$T_CLOUD" == gcp ]] && ensure_gcp_fw
    echo "[up] ${PAIR_NAME}: K@${K_CLOUD}/${K_LOC} (${K_IMG}) + T@${T_CLOUD}/${T_LOC} (${T_IMG})"
    local kip tip; kip="$(alloc_ip k "$K_CLOUD" "$K_LOC")"; tip="$(alloc_ip t "$T_CLOUD" "$T_LOC")"
    echo "[up] K IP ${kip}  T IP ${tip}"
    create_half k "$K_CLOUD" "$K_LOC" "$K_IMG" "$kip" "$tip" "$T_DIGEST" "$K_DEPLOY_KEY"
    create_half t "$T_CLOUD" "$T_LOC" "$T_IMG" "$tip" "$kip" "$K_DIGEST" "$T_DEPLOY_KEY"
    echo "[up] polling /health (K ${kip}, T ${tip})..."
    poll_health "$kip" "$tip"
}

# half_loc / half_cloud resolve a role's cloud+loc for status/down/reset.
half_cloud() { [[ "$1" == k ]] && echo "$K_CLOUD" || echo "$T_CLOUD"; }
half_loc() { [[ "$1" == k ]] && echo "$K_LOC" || echo "$T_LOC"; }

cmd_status() {
    for role in k t; do
        local cloud loc; cloud="$(half_cloud "$role")"; loc="$(half_loc "$role")"
        echo "=== ${role}@${cloud} (${loc}) ==="
        if [[ "$cloud" == gcp ]]; then
            g compute instances describe "${PAIR_NAME}-${role}-gcp" --zone="$loc" --format='value(status,networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || echo "  absent"
        else
            awsr "$loc" ec2 describe-instances --filters "Name=tag:Name,Values=${PAIR_NAME}-${role}-aws" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
                --query 'Reservations[].Instances[].[InstanceId,State.Name,PublicIpAddress]' --output text 2>/dev/null || echo "  absent"
        fi
    done
}

cmd_reset() {
    local role="${1:-}"; case "$role" in k|t) ;; *) echo "usage: $0 reset <k|t>" >&2; exit 1 ;; esac
    local cloud loc; cloud="$(half_cloud "$role")"; loc="$(half_loc "$role")"
    if [[ "$cloud" == gcp ]]; then
        echo "[reset] rebooting ${PAIR_NAME}-${role}-gcp..."
        g compute instances reset "${PAIR_NAME}-${role}-gcp" --zone="$loc" --quiet
    else
        local iid; iid="$(awsr "$loc" ec2 describe-instances --filters "Name=tag:Name,Values=${PAIR_NAME}-${role}-aws" "Name=instance-state-name,Values=running" --query 'Reservations[].Instances[].InstanceId' --output text)"
        echo "[reset] rebooting ${iid}..."
        awsr "$loc" ec2 reboot-instances --instance-ids "$iid"
    fi
}

cmd_down() {
    for role in k t; do
        local cloud loc; cloud="$(half_cloud "$role")"; loc="$(half_loc "$role")"
        if [[ "$cloud" == gcp ]]; then
            local region; region="$(gcp_region "$loc")"
            echo "[down] deleting ${PAIR_NAME}-${role}-gcp + its static IP..."
            g compute instances delete "${PAIR_NAME}-${role}-gcp" --zone="$loc" --quiet >/dev/null 2>&1 || true
            g compute addresses delete "${PAIR_NAME}-${role}-ip" --region="$region" --quiet >/dev/null 2>&1 || true
        else
            echo "[down] terminating ${PAIR_NAME}-${role}-aws + releasing its EIP..."
            local iid; iid="$(awsr "$loc" ec2 describe-instances --filters "Name=tag:Name,Values=${PAIR_NAME}-${role}-aws" "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true)"
            if [[ -n "$iid" && "$iid" != None ]]; then
                awsr "$loc" ec2 terminate-instances --instance-ids $iid >/dev/null
                awsr "$loc" ec2 wait instance-terminated --instance-ids $iid
            fi
            local alloc; alloc="$(awsr "$loc" ec2 describe-addresses --filters "Name=tag:Name,Values=${PAIR_NAME}-${role}-aws" --query 'Addresses[0].AllocationId' --output text 2>/dev/null || true)"
            [[ -n "$alloc" && "$alloc" != None ]] && awsr "$loc" ec2 release-address --allocation-id "$alloc" >/dev/null 2>&1 || true
            awsr "$loc" ec2 delete-security-group --group-name "${PAIR_NAME}-sg" >/dev/null 2>&1 || true
        fi
    done
    echo "[down] ${PAIR_NAME} torn down (images kept)."
}

case "${1:-}" in
    up)     cmd_up ;;
    status) cmd_status ;;
    down)   cmd_down ;;
    reset)  cmd_reset "${2:-}" ;;
    *) echo "usage: $0 {up|status|down|reset <k|t>}" >&2; exit 1 ;;
esac
