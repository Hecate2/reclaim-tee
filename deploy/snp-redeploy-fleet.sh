#!/bin/bash
set -euo pipefail

# =============================================================================
# Blue-green redeploy of the SEV-SNP TEE fleet (the SNP analogue of
# redeploy-fleet.sh, which is CS/GCP-only).
#
#   1. Build new SNP images at HEAD (snp-build.sh for the K cloud + T cloud).
#      App digest is cross-cloud-identical; base UKIs are per-cloud + pinned.
#   2. Allowlist the new app digests on the router (admin API).
#   3. Spin up N new pairs via snp-pair.sh, each a distinct SNP_PAIR_NAME
#      (${PREFIX}-<n>), in the configured orientation (SNP_K_CLOUD/SNP_T_CLOUD).
#   4. Wait until all N new pairs are Ready in the router.
#   5. Retire every OLD pair (registered app digest != new) — drain by pair_id
#      (resolved from the pair's stable IP on whichever cloud holds K), wait for
#      active_sessions==0, mark dead, then snp-pair.sh down that pair.
#   6. Trim old digests from the allowlist.
#
# Differences from CS that this encodes:
#   - Cross-cloud: each pair spans SNP_K_CLOUD + SNP_T_CLOUD; the whole fleet
#     shares ONE orientation per redeploy (a redeploy doesn't flip clouds).
#   - Pairs are namespaced by SNP_PAIR_NAME (snp-pair.sh has no auto-numbering);
#     this script owns the ${PREFIX}-<n> scheme.
#   - Retire maps router pair_id from the pair's IP (cloud-agnostic), since the
#     CS retire-pair.sh resolves only GCP VM IPs.
#   - Atomic K+T ([[atomic deploys]]) is WITHIN a pair; blue-green is ACROSS
#     pairs. Both hold.
#
# Router target follows snp-pair.sh: SNP_ROUTER_URL + an admin token
# (SNP_ADMIN_TOKEN, else deploy/.test-router-admin-token). For PROD set
# SNP_ROUTER_URL/SNP_JWT_ISSUER to prod and SNP_ADMIN_TOKEN=$ROUTER_ADMIN_TOKEN,
# and make sure snp-pair.sh is pointed at the prod router too (it derives the
# TEE's JWT pubkey from the test signing key by default — prod needs the
# prod /jwt-pubkey; see the SNP_TARGET note in snp-pair.sh).
#
# Requirements: docker (+ AWS VM-import perms if a half is on AWS), gcloud, aws,
# jq, python3, clean git tree (snp-build.sh refuses a dirty tree for prod).
#
# Usage:
#   ./deploy/snp-redeploy-fleet.sh --count 1
#   SNP_K_CLOUD=aws SNP_T_CLOUD=gcp ./deploy/snp-redeploy-fleet.sh --count 2
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
source "${SCRIPT_DIR}/_lib.sh"
# Per-cloud base UKI identities (SNP_BASE_DIGEST_GCP/AWS) to allowlist alongside apps.
set -a; source "${SCRIPT_DIR}/snp-image/pins.env"; set +a

GCP_PROJECT="${GCP_PROJECT:?set GCP_PROJECT in deploy/.env}"
# SNP_TARGET (test|prod) picks the router this fleet redeploy talks to AND is
# inherited by the snp-pair.sh up/down calls below (which then default to
# 443/info for prod, 8081/debug for test). Keep it consistent across both.
TARGET="${SNP_TARGET:-test}"
export SNP_TARGET="${TARGET}"
case "${TARGET}" in
test)
	ROUTER="${SNP_ROUTER_URL:?set SNP_ROUTER_URL in deploy/.env}"
	ADMIN_TOKEN="${SNP_ADMIN_TOKEN:-$(cat "${SCRIPT_DIR}/.test-router-admin-token" 2>/dev/null || true)}"
	;;
prod)
	ROUTER="${ROUTER_URL:?set ROUTER_URL in deploy/.env}"
	ADMIN_TOKEN="${ROUTER_ADMIN_TOKEN:?set ROUTER_ADMIN_TOKEN in deploy/.env}"
	;;
*)
	echo "SNP_TARGET must be 'test' or 'prod' (got '${TARGET}')" >&2; exit 1 ;;
esac
[[ -n "${ADMIN_TOKEN}" ]] || { echo "no admin token for target '${TARGET}'" >&2; exit 1; }

PREFIX="${SNP_FLEET_PREFIX:-snp}"
K_CLOUD="${SNP_K_CLOUD:-gcp}"
T_CLOUD="${SNP_T_CLOUD:-aws}"
K_LOC="${SNP_K_LOCATION:-$([[ "$K_CLOUD" == gcp ]] && echo "${SNP_PAIR_GCP_ZONE:?}" || echo "${SNP_PAIR_AWS_REGION:?}")}"
T_LOC="${SNP_T_LOCATION:-$([[ "$T_CLOUD" == gcp ]] && echo "${SNP_PAIR_GCP_ZONE:?}" || echo "${SNP_PAIR_AWS_REGION:?}")}"
# Shared with snp-build.sh (which writes it) + update-image-history.sh (reads it).
DIGEST_CACHE="${SCRIPT_DIR}/snp-digests.env"

DRAIN_TIMEOUT="${SNP_DRAIN_TIMEOUT:-300}"

COUNT=1
FORCE_REBUILD=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --count) COUNT="$2"; shift 2 ;;
        --force-rebuild) FORCE_REBUILD=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

log() { echo "[$(date '+%H:%M:%S')] $*"; }
# gcloud wants the proxy UNSET; aws wants it SET; router curls UNSET (LB is
# directly reachable). See [[wsl-proxy]].
g()  { ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true; gcloud_retry gcloud "$@" --project="${GCP_PROJECT}" ); }
a()  { local r="$1"; shift; ( export http_proxy="${SNP_PROXY:-http://127.0.0.1:10808}" https_proxy="${SNP_PROXY:-http://127.0.0.1:10808}"; aws --region "$r" "$@" ); }
rt() { ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true; curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" "$@" ); }

heartbeat_until_done() {
    local pid=$1 label="${2:-task}" start; start=$(date +%s)
    while kill -0 "${pid}" 2>/dev/null; do
        sleep 15; kill -0 "${pid}" 2>/dev/null || break
        log "  ...${label} still running ($(( $(date +%s) - start ))s elapsed)"
    done
}

# region of a gcp zone
gcp_region() { echo "${1%-*}"; }

# Resolve a pair's K-half public IP (the stable address snp-pair.sh allocated),
# whichever cloud K is on. Used to match the router pair_id for retire.
pair_k_ip() {
    local name="$1"
    if [[ "$K_CLOUD" == gcp ]]; then
        g compute addresses describe "${name}-k-ip" --region="$(gcp_region "${K_LOC}")" --format='value(address)' 2>/dev/null || true
    else
        a "${K_LOC}" ec2 describe-addresses --filters "Name=tag:Name,Values=${name}-k-aws" --query 'Addresses[0].PublicIp' --output text 2>/dev/null | grep -v '^None$' || true
    fi
}

# Discover existing fleet pair numbers from the T-half resources on T_CLOUD.
# (One role is enough; the fleet shares one orientation.)
discover_old_ns() {
    if [[ "$T_CLOUD" == gcp ]]; then
        g compute instances list --zones="${T_LOC}" --filter="name~^${PREFIX}-[0-9]+-t-gcp$" --format="value(name)" 2>/dev/null \
            | sed -E "s/^${PREFIX}-([0-9]+)-t-gcp$/\1/"
    else
        a "${T_LOC}" ec2 describe-instances \
            --filters "Name=tag:Name,Values=${PREFIX}-*-t-aws" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
            --query 'Reservations[].Instances[].Tags[?Key==`Name`]|[][].Value' --output text 2>/dev/null \
            | tr '\t' '\n' | sed -E "s/^${PREFIX}-([0-9]+)-t-aws$/\1/"
    fi | grep -E '^[0-9]+$' | sort -n | uniq || true
}

# ---- 1. Build (skip if cache COMMIT == HEAD) -------------------------------
HEAD_COMMIT=$(git -C "${SCRIPT_DIR}/.." rev-parse HEAD)
SKIP_BUILD=0
if [[ ${FORCE_REBUILD} -eq 0 && -f "${DIGEST_CACHE}" ]]; then
    CACHED=$(grep -E '^COMMIT=' "${DIGEST_CACHE}" | cut -d= -f2- || true)
    [[ "${CACHED}" == "${HEAD_COMMIT}" ]] && { log "Cached build matches HEAD (${HEAD_COMMIT:0:7}); skipping build."; SKIP_BUILD=1; } \
                                          || log "Cache is ${CACHED:0:7}; HEAD ${HEAD_COMMIT:0:7}; rebuilding."
fi
if [[ ${SKIP_BUILD} -eq 0 ]]; then
    log "Building tee_k@${K_CLOUD} ..."
    K_DIGEST=$("${SCRIPT_DIR}/snp-build.sh" k "${K_CLOUD}" 2>&1 | tee /dev/stderr | sed -n 's/.*app digest *= *\(snp-app:[0-9a-f]*\).*/\1/p' | tail -1)
    log "Building tee_t@${T_CLOUD} ..."
    T_DIGEST=$("${SCRIPT_DIR}/snp-build.sh" t "${T_CLOUD}" 2>&1 | tee /dev/stderr | sed -n 's/.*app digest *= *\(snp-app:[0-9a-f]*\).*/\1/p' | tail -1)
    [[ -n "${K_DIGEST}" && -n "${T_DIGEST}" ]] || { echo "build did not yield both digests" >&2; exit 1; }
    { echo "COMMIT=${HEAD_COMMIT}"; echo "SNP_K_DIGEST=${K_DIGEST}"; echo "SNP_T_DIGEST=${T_DIGEST}"; } > "${DIGEST_CACHE}"
fi
source "${DIGEST_CACHE}"
K_DIGEST="${SNP_K_DIGEST}"; T_DIGEST="${SNP_T_DIGEST}"
log "Digests: K=${K_DIGEST:0:24}... T=${T_DIGEST:0:24}..."

# ---- 2. Snapshot old pairs + compute new numbers ---------------------------
OLD_NS=$(discover_old_ns)
log "Old pairs: ${OLD_NS:-<none>}"
NEW_NS=(); N=1
while [[ ${#NEW_NS[@]} -lt ${COUNT} ]]; do
    echo "${OLD_NS}" | grep -qx "${N}" || NEW_NS+=("${N}")
    N=$((N+1))
done
log "New pair numbers: ${NEW_NS[*]}"

# ---- 3. Allowlist new digests (idempotent) ---------------------------------
log "Allowlisting new digests on ${ROUTER} ..."
# Apps (cross-cloud) + both per-cloud base UKIs; register pins both, fail-closed.
for d in "${K_DIGEST}" "${T_DIGEST}" "${SNP_BASE_DIGEST_GCP}" "${SNP_BASE_DIGEST_AWS}"; do
    rt -X POST -H "Content-Type: application/json" -d "{\"digest\":\"${d}\"}" "${ROUTER}/allowlist" >/dev/null
done

# ---- 4. Spin up N new pairs in parallel ------------------------------------
log "Spinning up ${COUNT} new pair(s) (${K_CLOUD}+${T_CLOUD})..."
PIDS=()
for n in "${NEW_NS[@]}"; do
    SNP_PAIR_NAME="${PREFIX}-${n}" SNP_K_CLOUD="${K_CLOUD}" SNP_T_CLOUD="${T_CLOUD}" \
        SNP_K_DIGEST="${K_DIGEST}" SNP_T_DIGEST="${T_DIGEST}" \
        SNP_TEST_STATIC_OPRF="${SNP_TEST_STATIC_OPRF:-0}" \
        "${SCRIPT_DIR}/snp-pair.sh" up &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do heartbeat_until_done "${pid}" "new pair bringup"; wait "${pid}"; done

# ---- 5. Confirm N new pairs Ready in the router ----------------------------
# Poll: snp-pair.sh returns when the HTTP health endpoints are up, but router
# Ready (control link + first heartbeat) lands a few seconds later.
log "Verifying ${COUNT} new pair(s) Ready..."
READY_TIMEOUT="${SNP_READY_TIMEOUT:-240}"
START=$(date +%s); READY=0
while [[ $(( $(date +%s) - START )) -lt ${READY_TIMEOUT} ]]; do
    READY=$(rt "${ROUTER}/pairs" | python3 -c "
import json,sys
d=json.load(sys.stdin); nd='${K_DIGEST}'
print(sum(1 for p in d.get('pairs',[]) if p.get('teek_image_digest')==nd and p.get('ready_at') and not p.get('draining',False)))
")
    [[ "${READY}" -ge "${COUNT}" ]] && break
    log "  ...${READY}/${COUNT} Ready, waiting ($(( $(date +%s) - START ))s)"
    sleep 5
done
[[ "${READY}" -ge "${COUNT}" ]] || { log "ERROR: only ${READY}/${COUNT} new pairs Ready after ${READY_TIMEOUT}s. Aborting before retiring old."; exit 1; }
log "${READY} new pair(s) Ready."

# ---- 6. Retire old pairs ---------------------------------------------------
if [[ -z "${OLD_NS}" ]]; then
    log "No old pairs to retire."
else
    for n in ${OLD_NS}; do
        name="${PREFIX}-${n}"
        kip=$(pair_k_ip "${name}")
        if [[ -z "${kip}" ]]; then
            log "Pair ${name}: no K IP found; skipping router drain, will down anyway."
        else
            mapfile -t PIDS_R < <(rt "${ROUTER}/pairs" | jq -r --arg ip "${kip}" '.pairs[] | select(.teek_addr | startswith($ip + ":")) | .id' 2>/dev/null || true)
            for pid_r in "${PIDS_R[@]}"; do
                [[ -z "${pid_r}" ]] && continue
                log "Draining ${name} (pair_id ${pid_r})..."
                rt -X POST "${ROUTER}/pairs/${pid_r}/drain" >/dev/null || log "WARN: drain non-zero for ${pid_r}"
                START=$(date +%s); ACTIVE=999
                while [[ $(( $(date +%s) - START )) -lt ${DRAIN_TIMEOUT} ]]; do
                    ACTIVE=$(rt "${ROUTER}/pairs" | jq -r --arg id "${pid_r}" '.pairs[]|select(.id==$id)|.active_sessions' 2>/dev/null || echo 999)
                    [[ "${ACTIVE}" == "0" || -z "${ACTIVE}" ]] && break
                    sleep 3
                done
                [[ "${ACTIVE}" == "0" || -z "${ACTIVE}" ]] && log "  drained." || log "  WARN: ${ACTIVE} active after ${DRAIN_TIMEOUT}s; killing anyway."
                for attempt in 1 2 3 4 5; do
                    CODE=$(rt -o /dev/null -w "%{http_code}" -X POST "${ROUTER}/pairs/${pid_r}/dead" || echo 000)
                    case "${CODE}" in 204|404) break ;; *) sleep 2 ;; esac
                done
            done
        fi
        log "Tearing down ${name} ..."
        SNP_PAIR_NAME="${name}" SNP_K_CLOUD="${K_CLOUD}" SNP_T_CLOUD="${T_CLOUD}" \
            SNP_K_DIGEST=x SNP_T_DIGEST=x "${SCRIPT_DIR}/snp-pair.sh" down
    done
fi

# ---- 7. Trim old digests from the allowlist --------------------------------
log "Trimming allowlist to current digests..."
for d in $(rt "${ROUTER}/allowlist" | jq -r '.digests[]'); do
    case "${d}" in
        "${K_DIGEST}"|"${T_DIGEST}"|snp-base:*) ;;  # keep current apps + all bases
        snp-app:*) log "Removing old app digest ${d:0:24}..."; rt -X DELETE "${ROUTER}/allowlist/${d}" >/dev/null ;;
    esac
done

log "SNP fleet redeploy complete: ${COUNT} pair(s) at K=${K_DIGEST:0:19}.../T=${T_DIGEST:0:19}..."
