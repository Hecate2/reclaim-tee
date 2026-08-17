#!/bin/bash
set -euo pipefail

# =============================================================================
# In-place SEV-SNP fleet redeploy.
#
# Discovers the live pairs from cloud resources + the router, prints them for
# visual confirmation, then redeploys each pair ONE AT A TIME, IN PLACE, in the
# SAME orientation + location it already runs, to the commit recorded in
# deploy/image-history.json (the same commit `verify.sh` verifies):
#
#   read target commit + expected digests from image-history.json ->
#   build (that commit, per-cloud images) -> assert built digests == recorded ->
#   allowlist -> for each pair: drain -> wait active_sessions==0 ->
#     remove BOTH old halves (keep static IP / EIP) -> dead -> snp-pair.sh up ->
#     wait Ready in router -> next pair -> trim old app digests.
#
# Intended workflow:  fix -> commit -> record digests in image-history.json
# (build-only + update-image-history.sh) -> commit -> push -> run this. The
# fleet builds/verifies/deploys exactly what json (already pushed) pins, so the
# deployed identity is publicly reproducible before a single VM is touched.
#
# Every run writes logs to a fresh temp dir (path printed up front and on any
# failure): run.log (orchestration) + per-step build-*.log / up-*.log. Point me
# at them, or dig in yourself, if a deploy stops midway.
#
#   ./deploy/snp-redeploy-fleet.sh record                # build-only HEAD + write image-history.json (then commit+push it)
#   ./deploy/snp-redeploy-fleet.sh                       # prod (default), interactive deploy of what json pins
#   SNP_DISCOVER_ONLY=1 ./deploy/snp-redeploy-fleet.sh   # preflight+discover only
#   SNP_YES=1 ./deploy/snp-redeploy-fleet.sh             # skip the confirm prompt
#   SNP_BUILD_COMMIT=<sha> ./deploy/snp-redeploy-fleet.sh # ad-hoc (skips json assert)
#   SNP_ONLY=snp-sg-1 ./deploy/snp-redeploy-fleet.sh      # resume: only these pair(s), comma-separated
#   SNP_SKIP_BUILD=1 ./deploy/snp-redeploy-fleet.sh       # reuse registered images (digest asserts still run)
#
# Requires docker+buildx. Expired gcloud and AWS MFA credentials are refreshed
# interactively during preflight.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
source "${SCRIPT_DIR}/_lib.sh"
set -a; source "${SCRIPT_DIR}/snp-image/pins.env"; set +a

GCP_PROJECT="${GCP_PROJECT:?set GCP_PROJECT in deploy/.env}"
TARGET="${SNP_TARGET:-prod}"; export SNP_TARGET="${TARGET}"
case "${TARGET}" in
  prod) ROUTER="${ROUTER_URL:?set ROUTER_URL in deploy/.env}"; ADMIN_TOKEN="${ROUTER_ADMIN_TOKEN:?set ROUTER_ADMIN_TOKEN in deploy/.env}" ;;
  test) ROUTER="${SNP_ROUTER_URL:?set SNP_ROUTER_URL in deploy/.env}"; ADMIN_TOKEN="${SNP_ADMIN_TOKEN:-$(cat "${SCRIPT_DIR}/.test-router-admin-token" 2>/dev/null || true)}" ;;
  *) echo "SNP_TARGET must be prod|test (got ${TARGET})" >&2; exit 1 ;;
esac
[[ -n "${ADMIN_TOKEN}" ]] || { echo "no admin token for ${TARGET}" >&2; exit 1; }

AWS_REGION="${SNP_PAIR_AWS_REGION:?set SNP_PAIR_AWS_REGION in deploy/.env}"
AWS_PROFILE="${AWS_PROFILE:?set AWS_PROFILE in deploy/.env}"
AWS_MFA_SOURCE_PROFILE="${AWS_MFA_SOURCE_PROFILE:?set AWS_MFA_SOURCE_PROFILE in deploy/.env}"
SNP_PROXY="${SNP_PROXY:-http://127.0.0.1:10808}"
STATIC_OPRF="${SNP_TEST_STATIC_OPRF:-0}"
DRAIN_TIMEOUT="${SNP_DRAIN_TIMEOUT:-600}"
READY_TIMEOUT="${SNP_READY_TIMEOUT:-420}"

# Per-run log dir, revealed up front so a mid-deploy failure is inspectable.
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/snp-redeploy-$(date +%Y%m%d-%H%M%S)-XXXX")"

log() { local m="[$(date '+%H:%M:%S')] $*"; echo "${m}"; echo "${m}" >> "${LOG_DIR}/run.log"; }
die() { echo "ERROR: $*" >&2; echo "ERROR: $*" >> "${LOG_DIR}/run.log" 2>/dev/null || true; echo "LOGS: ${LOG_DIR}" >&2; exit 1; }

# gcloud + router curls want the proxy UNSET; aws wants it SET. See [[wsl-proxy]].
g()  { ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true; gcloud_retry gcloud "$@" --project="${GCP_PROJECT}" ); }
a() {
  ( export http_proxy="${SNP_PROXY}" https_proxy="${SNP_PROXY}"; aws --profile "${AWS_PROFILE}" --region "${AWS_REGION}" "$@" )
}
rt() { ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true; curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" "$@" ); }

# ---- preflight -------------------------------------------------------------
GCP_AUTH_ACCOUNT=""
AWS_AUTH_ARN=""

ensure_gcp_auth() {
  GCP_AUTH_ACCOUNT="$( ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true; gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null ) | head -1 || true)"
  if [[ -n "${GCP_AUTH_ACCOUNT}" ]] && (
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true
    gcloud auth print-access-token >/dev/null 2>&1
  ); then
    return
  fi

  log "GCP credentials missing or expired; starting gcloud auth login ..."
  if [[ -n "${GCP_AUTH_ACCOUNT}" ]]; then
    ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true; gcloud auth login "${GCP_AUTH_ACCOUNT}" --no-launch-browser ) \
      || die "gcloud authentication failed"
  else
    ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true; gcloud auth login --no-launch-browser ) \
      || die "gcloud authentication failed"
  fi

  GCP_AUTH_ACCOUNT="$( ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true; gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null ) | head -1 || true)"
  [[ -n "${GCP_AUTH_ACCOUNT}" ]] || die "gcloud authentication completed without an active account"
  ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true; gcloud auth print-access-token >/dev/null 2>&1 ) \
    || die "gcloud credentials are still unusable after login"
}

ensure_aws_auth() {
  AWS_AUTH_ARN="$(a sts get-caller-identity --query Arn --output text 2>/dev/null || true)"
  [[ "${AWS_AUTH_ARN}" == arn:aws:* ]] && return

  log "AWS credentials for ${AWS_PROFILE} missing or expired; starting MFA login ..."
  ( export http_proxy="${SNP_PROXY}" https_proxy="${SNP_PROXY}"; aws configure mfa-login \
      --profile "${AWS_MFA_SOURCE_PROFILE}" --update-profile "${AWS_PROFILE}" ) \
    || die "AWS MFA authentication failed for ${AWS_PROFILE}"
  AWS_AUTH_ARN="$(a sts get-caller-identity --query Arn --output text 2>/dev/null || true)"
  [[ "${AWS_AUTH_ARN}" == arn:aws:* ]] || die "AWS credentials for ${AWS_PROFILE} are still unusable after MFA login"
}

preflight() {
  log "Preflight: docker / gcloud / aws ..."
  command -v docker >/dev/null || die "docker not found"
  command -v gcloud >/dev/null || die "gcloud not found"
  command -v aws >/dev/null || die "aws not found"
  docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || die "docker daemon not reachable"
  docker buildx version >/dev/null 2>&1 || die "docker buildx missing"
  ensure_gcp_auth
  ensure_aws_auth
  git -C "${REPO_ROOT}" rev-parse HEAD >/dev/null 2>&1 || die "no git HEAD"
  log "  docker OK | gcloud=${GCP_AUTH_ACCOUNT} | aws=${AWS_AUTH_ARN} (profile=${AWS_PROFILE})"
}

# ---- target from image-history.json ---------------------------------------
TARGET_COMMIT=""; EXPECT_K=""; EXPECT_T=""
read_target() {
  local hist="${SCRIPT_DIR}/image-history.json"
  [[ -f "${hist}" ]] || die "missing ${hist}"
  local out; out="$(python3 -c "
import json,sys
apps=json.load(open('${hist}')).get('app_images',[])
def last(role):
    xs=[e for e in apps if e.get('role')==role and e.get('type')=='sev-snp']
    return xs[-1] if xs else None
k=last('k'); t=last('t')
if not k or not t: sys.exit('no sev-snp app_images entries')
print(k.get('sourceCommit',''), t.get('sourceCommit',''), k.get('version',''), t.get('version',''))
" 2>/dev/null || true)"
  [[ -n "${out}" ]] || die "could not read sev-snp target from ${hist}"
  local kc tc kv tv; read -r kc tc kv tv <<<"${out}"
  [[ -n "${kc}" && "${kc}" == "${tc}" ]] || die "image-history.json k/t sourceCommit differ or empty (k=${kc} t=${tc})"
  TARGET_COMMIT="${SNP_BUILD_COMMIT:-${kc}}"
  if [[ "${TARGET_COMMIT}" == "${kc}" ]]; then EXPECT_K="${kv}"; EXPECT_T="${tv}"; fi
}

# ---- discover pairs from cloud resources + router --------------------------
declare -a P_NAME P_KCLOUD P_KLOC P_KIP P_TCLOUD P_TLOC P_TIP P_ID P_ACTIVE P_KDIG P_TDIG
discover() {
  log "Discovering pairs (GCP + AWS ${AWS_REGION} + router ${ROUTER}) ..."
  local tmp gcp_rows aws_rows; tmp="$(mktemp)"
  if ! gcp_rows="$(g compute instances list --filter="name~snp-" --format="value(name,zone,networkInterfaces[0].accessConfigs[0].natIP)" 2>/dev/null)"; then
    rm -f "${tmp}"
    die "GCP instance discovery failed"
  fi
  while read -r nm zone ip; do
    [[ "${nm}" =~ ^(snp-.+)-(k|t)-gcp$ ]] && echo "${BASH_REMATCH[1]}|${BASH_REMATCH[2]}|gcp|${zone}|${ip}"
  done <<<"${gcp_rows}" >> "${tmp}"

  if ! aws_rows="$(a ec2 describe-instances --filters "Name=tag:Name,Values=snp-*" "Name=instance-state-name,Values=pending,running" \
      --query 'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,PublicIpAddress]' --output text 2>/dev/null)"; then
    rm -f "${tmp}"
    die "AWS EC2 discovery failed (refresh AWS credentials/MFA)"
  fi
  while read -r nm ip; do
    [[ "${nm}" =~ ^(snp-.+)-(k|t)-aws$ ]] && echo "${BASH_REMATCH[1]}|${BASH_REMATCH[2]}|aws|${AWS_REGION}|${ip}"
  done <<<"${aws_rows}" >> "${tmp}"

  local pairs; mapfile -t pairs < <(cut -d'|' -f1 "${tmp}" | sort -u)
  [[ ${#pairs[@]} -gt 0 ]] || { rm -f "${tmp}"; die "no SNP pairs discovered from cloud resources"; }

  # SNP_ONLY narrows the fleet to named pairs (resume a partial rollout without
  # re-draining healthy ones). Unknown name = typo, so fail rather than no-op.
  if [[ -n "${SNP_ONLY:-}" ]]; then
    local want=() keep=() w p found
    IFS=',' read -r -a want <<<"${SNP_ONLY}"
    for w in "${want[@]}"; do
      found=0
      for p in "${pairs[@]}"; do [[ "${p}" == "${w}" ]] && { found=1; break; }; done
      (( found )) || { rm -f "${tmp}"; die "SNP_ONLY names unknown pair '${w}' (discovered: ${pairs[*]})"; }
    done
    for p in "${pairs[@]}"; do
      for w in "${want[@]}"; do [[ "${p}" == "${w}" ]] && { keep+=("${p}"); break; }; done
    done
    pairs=("${keep[@]}")
    log "  SNP_ONLY=${SNP_ONLY} — limiting to ${#pairs[@]} pair(s): ${pairs[*]}"
  fi

  local routerjson; routerjson="$(rt "${ROUTER}/pairs" || echo '{}')"
  local pn kline tline kcloud kloc kip tcloud tloc tip row
  for pn in "${pairs[@]}"; do
    kline="$(awk -F'|' -v p="${pn}" '$1==p && $2=="k"{print; exit}' "${tmp}")"
    tline="$(awk -F'|' -v p="${pn}" '$1==p && $2=="t"{print; exit}' "${tmp}")"
    [[ -n "${kline}" && -n "${tline}" ]] || { log "  WARN: ${pn} missing a half (k='${kline:-}' t='${tline:-}'); skipping"; continue; }
    IFS='|' read -r _ _ kcloud kloc kip <<<"${kline}"
    IFS='|' read -r _ _ tcloud tloc tip <<<"${tline}"
    row="$(python3 -c "
import json
d=json.loads('''${routerjson}''')
for p in d.get('pairs',[]):
    if str(p.get('teek_addr','')).startswith('${kip}:'):
        print(p['id'], p.get('active_sessions',0), p.get('teek_image_digest','?'), p.get('teet_image_digest','?')); break
" 2>/dev/null || true)"
    [[ -n "${row}" ]] || row="<none> - ? ?"
    P_NAME+=("${pn}"); P_KCLOUD+=("${kcloud}"); P_KLOC+=("${kloc}"); P_KIP+=("${kip}")
    P_TCLOUD+=("${tcloud}"); P_TLOC+=("${tloc}"); P_TIP+=("${tip}")
    P_ID+=("$(awk '{print $1}' <<<"${row}")"); P_ACTIVE+=("$(awk '{print $2}' <<<"${row}")")
    P_KDIG+=("$(awk '{print $3}' <<<"${row}")"); P_TDIG+=("$(awk '{print $4}' <<<"${row}")")
  done
  rm -f "${tmp}"
  [[ ${#P_NAME[@]} -gt 0 ]] || die "no complete pairs discovered"
}

short() { local d="${1#snp-app:}"; echo "${d:0:12}"; }

confirm() {
  {
    echo
    echo "==================== SNP FLEET REDEPLOY (in place) ===================="
    echo "Router        : ${ROUTER}   target=${TARGET}   real_oprf=$([[ "${STATIC_OPRF}" == 1 ]] && echo no || echo yes)"
    echo "Deploy commit : ${TARGET_COMMIT:0:12}  (from image-history.json$([[ -n "${SNP_BUILD_COMMIT:-}" ]] && echo ' — overridden by SNP_BUILD_COMMIT'))"
    [[ -n "${EXPECT_K}" ]] && echo "Expected      : K=$(short "${EXPECT_K}")  T=$(short "${EXPECT_T}")"
    echo "Logs          : ${LOG_DIR}"
    echo "Pairs (${#P_NAME[@]}) — redeployed IN PLACE, one at a time, same orientation:"
    printf '  %-13s %-30s %-30s %-10s %-7s %s\n' NAME K-half T-half pair_id active curK/curT
    local i
    for i in "${!P_NAME[@]}"; do
      printf '  %-13s %-30s %-30s %-10s %-7s %s/%s\n' \
        "${P_NAME[$i]}" "${P_KCLOUD[$i]}/${P_KLOC[$i]} ${P_KIP[$i]}" "${P_TCLOUD[$i]}/${P_TLOC[$i]} ${P_TIP[$i]}" \
        "${P_ID[$i]:0:8}" "${P_ACTIVE[$i]}" "$(short "${P_KDIG[$i]}")" "$(short "${P_TDIG[$i]}")"
    done
    echo "======================================================================"
  } | tee -a "${LOG_DIR}/run.log"
  [[ "${SNP_DISCOVER_ONLY:-0}" == 1 ]] && { log "SNP_DISCOVER_ONLY=1 — stopping after discovery."; exit 0; }
  if [[ "${SNP_YES:-0}" == 1 ]]; then log "SNP_YES=1 — proceeding without prompt."; return; fi
  local ans; read -r -p "Redeploy these ${#P_NAME[@]} pair(s) to ${TARGET_COMMIT:0:7}, in place, one by one? [y/N] " ans || true
  [[ "${ans}" == y || "${ans}" == Y ]] || { echo "aborted."; exit 1; }
}

NEW_K=""; NEW_T=""
build_and_verify() {
  declare -A need; local i
  for i in "${!P_NAME[@]}"; do need["k:${P_KCLOUD[$i]}"]=1; need["t:${P_TCLOUD[$i]}"]=1; done
  if [[ "${SNP_SKIP_BUILD:-0}" == 1 ]]; then
    log "  SNP_SKIP_BUILD=1 — reusing already-registered cloud images for: ${!need[*]}"
    log "  WARNING: assumes those images were built from snp-digests.env's COMMIT; only safe right after a successful build."
  else
  log "Building commit ${TARGET_COMMIT:0:7} for: ${!need[*]}"
  local rc role cloud blog
  for rc in "${!need[@]}"; do
    role="${rc%%:*}"; cloud="${rc##*:}"; blog="${LOG_DIR}/build-${role}-${cloud}.log"
    log "  build ${role} ${cloud}  (log: ${blog})"
    ( export http_proxy="${SNP_PROXY}" https_proxy="${SNP_PROXY}" SNP_BUILD_COMMIT="${TARGET_COMMIT}"; "${SCRIPT_DIR}/snp-build.sh" "${role}" "${cloud}" ) > "${blog}" 2>&1 || die "build ${role} ${cloud} failed — see ${blog}"
  done
  fi
  set -a; source "${SCRIPT_DIR}/snp-digests.env"; set +a
  [[ "${COMMIT}" == "${TARGET_COMMIT}" ]] || die "snp-digests.env COMMIT ${COMMIT:0:7} != target ${TARGET_COMMIT:0:7}"
  NEW_K="${SNP_K_DIGEST:?missing K digest after build}"; NEW_T="${SNP_T_DIGEST:?missing T digest after build}"
  if [[ -n "${EXPECT_K}" ]]; then
    [[ "${NEW_K}" == "${EXPECT_K}" ]] || die "VERIFY FAIL: built K ${NEW_K} != image-history ${EXPECT_K} — NOT deploying"
    [[ "${NEW_T}" == "${EXPECT_T}" ]] || die "VERIFY FAIL: built T ${NEW_T} != image-history ${EXPECT_T} — NOT deploying"
    log "  verified: built digests match image-history.json (K=$(short "${NEW_K}") T=$(short "${NEW_T}"))"
  else
    log "  ad-hoc build (SNP_BUILD_COMMIT override): skipping json digest assert. K=$(short "${NEW_K}") T=$(short "${NEW_T}")"
  fi
}

allowlist_add() {
  log "Allowlisting new app digests + both bases ..."
  local d
  for d in "${NEW_K}" "${NEW_T}" "${SNP_BASE_DIGEST_GCP}" "${SNP_BASE_DIGEST_AWS}"; do
    rt -X POST -H "Content-Type: application/json" -d "{\"digest\":\"${d}\"}" "${ROUTER}/allowlist" >/dev/null || die "allowlist ${d} failed"
  done
}

# remove one old half, KEEPING its stable IP (gcp static address / aws EIP).
remove_old_half() {
  local cloud="$1" loc="$2" name="$3" role="$4"
  if [[ "${cloud}" == gcp ]]; then
    log "    delete GCP ${name}-${role}-gcp (keep static IP) ..."
    g compute instances delete "${name}-${role}-gcp" --zone="${loc}" --quiet >/dev/null 2>&1 || true
  else
    local iid; iid="$(a ec2 describe-instances --filters "Name=tag:Name,Values=${name}-${role}-aws" "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true)"
    if [[ -n "${iid}" && "${iid}" != None ]]; then
      log "    terminate AWS ${iid} (keep EIP) ..."
      a ec2 terminate-instances --instance-ids ${iid} >/dev/null
      a ec2 wait instance-terminated --instance-ids ${iid} || true
    fi
  fi
}

redeploy_pair() {
  local i="$1"
  local name="${P_NAME[$i]}" pid="${P_ID[$i]}"
  local kc="${P_KCLOUD[$i]}" kl="${P_KLOC[$i]}" kip="${P_KIP[$i]}"
  local tc="${P_TCLOUD[$i]}" tl="${P_TLOC[$i]}"
  echo; log "=== ${name}: K@${kc}/${kl} + T@${tc}/${tl}  (pair_id ${pid}) ==="

  if [[ "${pid}" != "<none>" ]]; then
    log "  draining ${pid} (wait active==0, up to ${DRAIN_TIMEOUT}s) ..."
    rt -X POST "${ROUTER}/pairs/${pid}/drain" >/dev/null || log "  WARN: drain returned non-2xx"
    local start active; start=$(date +%s); active=999
    while (( $(date +%s) - start < DRAIN_TIMEOUT )); do
      active="$(rt "${ROUTER}/pairs" | python3 -c "import json,sys;print(next((p.get('active_sessions',0) for p in json.load(sys.stdin).get('pairs',[]) if p['id']=='${pid}'),0))" 2>/dev/null || echo 999)"
      [[ "${active}" == "0" ]] && break
      log "    active=${active}, waiting ..."; sleep 5
    done
    [[ "${active}" == "0" ]] || die "${name}: ${active} sessions still active after ${DRAIN_TIMEOUT}s — aborting (never terminate live sessions)"
    log "  drained."
  else
    log "  no router pair_id matched ${kip}; skipping drain."
  fi

  # Remove BOTH old halves first (keep IP/EIP) so `up` recreates cleanly with no
  # stale-digest peer overlap (else the new K logs a transient RA-TLS mismatch).
  remove_old_half "${kc}" "${kl}" "${name}" k
  remove_old_half "${tc}" "${tl}" "${name}" t

  # /dead AFTER the VMs are gone. It deletes the pair record, and a live TEE that
  # heartbeats a deleted pair_id gets 404 -> re-registers -> orphan pair on the
  # OLD digest (which is still allowlisted). Deleting first closes that window.
  if [[ "${pid}" != "<none>" ]]; then
    local code
    for _ in 1 2 3 4 5; do code="$(rt -o /dev/null -w '%{http_code}' -X POST "${ROUTER}/pairs/${pid}/dead")"; case "${code}" in 204|404) break ;; *) sleep 2 ;; esac; done
    log "  marked dead (code ${code:-?})."
  fi

  local ulog="${LOG_DIR}/up-${name}.log"
  log "  bringing up ${name} at new digests  (log: ${ulog}) ..."
  SNP_PAIR_NAME="${name}" SNP_K_CLOUD="${kc}" SNP_T_CLOUD="${tc}" \
    SNP_K_LOCATION="${kl}" SNP_T_LOCATION="${tl}" \
    SNP_K_DIGEST="${NEW_K}" SNP_T_DIGEST="${NEW_T}" \
    SNP_TARGET="${TARGET}" SNP_TEST_STATIC_OPRF="${STATIC_OPRF}" \
    "${SCRIPT_DIR}/snp-pair.sh" up > "${ulog}" 2>&1 || die "${name}: snp-pair.sh up failed — see ${ulog}"

  log "  waiting Ready in router (up to ${READY_TIMEOUT}s) ..."
  local start2 ok; start2=$(date +%s); ok=0
  while (( $(date +%s) - start2 < READY_TIMEOUT )); do
    if rt "${ROUTER}/pairs" | python3 -c "import json,sys
d=json.load(sys.stdin)
sys.exit(0 if [p for p in d.get('pairs',[]) if str(p.get('teek_addr','')).startswith('${kip}:') and p.get('teek_image_digest')=='${NEW_K}' and p.get('ready_at')] else 1)" 2>/dev/null; then ok=1; break; fi
    sleep 5
  done
  [[ "${ok}" == 1 ]] || die "${name}: not Ready at ${kip} with new digest after ${READY_TIMEOUT}s (see ${ulog} + Cloud Logging / CloudWatch)"
  log "  ${name} READY on new build."
}

trim_allowlist() {
  if [[ -n "${SNP_ONLY:-}" ]]; then
    log "Partial rollout (SNP_ONLY=${SNP_ONLY}): keeping existing app digests for untouched pairs."
    return
  fi
  log "Trimming old app digests from allowlist (keep new apps + bases) ..."
  local d
  for d in $(rt "${ROUTER}/allowlist" | python3 -c "import json,sys;[print(x) for x in json.load(sys.stdin).get('digests',[])]"); do
    case "${d}" in
      "${NEW_K}"|"${NEW_T}"|snp-base:*) ;;
      snp-app:*) log "  removing ${d:0:26}..."; rt -X DELETE "${ROUTER}/allowlist/${d}" >/dev/null || true ;;
    esac
  done
}

# ---- record: build-only HEAD, write digests to image-history.json ---------
cmd_record() {
  log "record: build-only HEAD, write digests to image-history.json (no cloud, no deploy)"
  command -v docker >/dev/null && docker version >/dev/null 2>&1 || die "docker not reachable"
  local head; head="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  # record pins committed HEAD (clean clone), so only uncommitted SOURCE matters
  # — deploy scripts are intentionally uncommitted and must not block this.
  [[ -z "$(git -C "${REPO_ROOT}" status --porcelain -- tee_k tee_t shared minitls oprfmpc providers client lib cmd proto 2>/dev/null || true)" ]] || die "commit your code first — record pins committed HEAD ${head:0:7}, but there are uncommitted source changes"
  local cur; cur="$(python3 -c "import json;a=[e for e in json.load(open('${SCRIPT_DIR}/image-history.json')).get('app_images',[]) if e.get('type')=='sev-snp' and e.get('role')=='k'];print(a[-1]['sourceCommit'] if a else '')" 2>/dev/null || true)"
  [[ "${cur}" == "${head}" ]] && { log "image-history.json already pins ${head:0:7}; nothing to record. Just push + run the fleet."; return; }
  local role blog kd td
  for role in k t; do
    blog="${LOG_DIR}/record-build-${role}.log"
    log "  build-only ${role} @ ${head:0:7}  (log: ${blog})"
    ( export http_proxy="${SNP_PROXY}" https_proxy="${SNP_PROXY}" SNP_BUILD_ONLY=1 SNP_BUILD_COMMIT="${head}"; "${SCRIPT_DIR}/snp-build.sh" "${role}" gcp ) > "${blog}" 2>&1 || die "build-only ${role} failed — see ${blog}"
  done
  kd="$(grep -oE 'snp-app:[0-9a-f]{64}' "${LOG_DIR}/record-build-k.log" | tail -1 || true)"
  td="$(grep -oE 'snp-app:[0-9a-f]{64}' "${LOG_DIR}/record-build-t.log" | tail -1 || true)"
  [[ -n "${kd}" && -n "${td}" ]] || die "could not parse digests from build logs in ${LOG_DIR}"
  printf 'SNP_K_DIGEST=%s\nSNP_T_DIGEST=%s\nCOMMIT=%s\n' "${kd}" "${td}" "${head}" > "${SCRIPT_DIR}/snp-digests.env"
  "${SCRIPT_DIR}/update-image-history.sh" snp > "${LOG_DIR}/record-history.log" 2>&1 || die "update-image-history failed — see ${LOG_DIR}/record-history.log"
  log "recorded ${head:0:7}: K=$(short "${kd}") T=$(short "${td}") in deploy/image-history.json"
  echo
  echo "NEXT:  git add deploy/image-history.json && git commit -m '[CHORE] record snp app digests @${head:0:7}' && git push"
  echo "THEN:  ./deploy/snp-redeploy-fleet.sh"
}

# ---- run -------------------------------------------------------------------
echo "LOGS: ${LOG_DIR}   (run.log + per-step build-*.log / up-*.log)"
if [[ "${1:-}" == record ]]; then cmd_record; log "Logs: ${LOG_DIR}"; exit 0; fi
log "snp-redeploy-fleet starting (target=${TARGET}, router=${ROUTER})"
preflight
read_target
discover
confirm
build_and_verify
allowlist_add
for i in "${!P_NAME[@]}"; do redeploy_pair "${i}"; done
trim_allowlist

echo
log "FLEET REDEPLOY COMPLETE — ${#P_NAME[@]} pair(s) on ${TARGET_COMMIT:0:7}"
log "  K=${NEW_K}"
log "  T=${NEW_T}"
echo "Final fleet:" | tee -a "${LOG_DIR}/run.log"
rt "${ROUTER}/pairs" | python3 -c "
import json,sys
for p in json.load(sys.stdin).get('pairs',[]):
    print('  ', p['id'][:8], p.get('teek_addr'), 'ready' if p.get('ready_at') else 'NOTREADY', 'active='+str(p.get('active_sessions')), 'K='+str(p.get('teek_image_digest'))[:20])" | tee -a "${LOG_DIR}/run.log"
log "image-history.json already pins ${TARGET_COMMIT:0:7} (recorded pre-deploy); nothing to commit."
log "Logs: ${LOG_DIR}"
