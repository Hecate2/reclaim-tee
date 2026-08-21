#!/bin/bash
set -e

# =============================================================================
# Appends TEE app-image digests to app_images[] in deploy/image-history.json.
#
#   ./update-image-history.sh        # CS (default): reads deploy/v2-digests.env
#   ./update-image-history.sh snp    # SEV-SNP: reads deploy/snp-digests.env
#
# image-history.json is an object: { base_images, app_images }. base_images
# (per-cloud SNP base UKIs) are commit-independent. Append a new record when a
# pin changes so rollback identities remain available. This script only touches
# app_images. The *-digests.env
# source files are local-only (NOT committed); only image-history.json is. We
# record digest + sourceCommit + sourceDateEpoch so verify.sh can rebuild the
# exact image from source. Dedupes by version, so re-runs are idempotent.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
OUTPUT="${SCRIPT_DIR}/image-history.json"
MODE="${1:-cs}"

require_commit() {
    # The recorded commit must exist, or verify.sh can never reproduce the
    # entry. Fails closed so we don't record an unverifiable (e.g. unmerged) image.
    if ! git -C "${REPO_ROOT}" rev-parse --verify "${1}^{commit}" >/dev/null 2>&1; then
        echo "ERROR: COMMIT ${1} is not in this repo. Build + record from a committed (merged) commit." >&2
        exit 1
    fi
}

case "${MODE}" in
cs)
    DIGESTS="${SCRIPT_DIR}/v2-digests.env"
    [[ -f "${DIGESTS}" ]] || { echo "Missing ${DIGESTS} — run build-tees-v2.sh first"; exit 1; }
    source "${DIGESTS}"
    : "${TEE_K_TAG:?not set in v2-digests.env}"; : "${TEE_T_TAG:?not set in v2-digests.env}"
    : "${TEE_K_DIGEST:?not set in v2-digests.env}"; : "${TEE_T_DIGEST:?not set in v2-digests.env}"
    : "${COMMIT:?not set in v2-digests.env}"
    require_commit "${COMMIT}"
    SOURCE_DATE_EPOCH=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct "${COMMIT}")
    COMMIT_TIME=$(git -C "${REPO_ROOT}" log -1 --pretty=%cI "${COMMIT}")
    # Split "<registry>/<repo>/tee-k:<tag>" into package + tag (pkg.dev has no port).
    NEW_ENTRIES=$(TK_PKG="${TEE_K_TAG%:*}" TK_TAG="${TEE_K_TAG##*:}" TT_PKG="${TEE_T_TAG%:*}" TT_TAG="${TEE_T_TAG##*:}" \
        TEE_K_DIGEST="${TEE_K_DIGEST}" TEE_T_DIGEST="${TEE_T_DIGEST}" COMMIT="${COMMIT}" \
        COMMIT_TIME="${COMMIT_TIME}" SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python3 -c "
import json, os
e = os.environ
def cs(pkg, tag, ver):
    return {'type':'cs','package':pkg,'tags':[tag],'version':ver,'createTime':e['COMMIT_TIME'],
            'updateTime':e['COMMIT_TIME'],'sourceCommit':e['COMMIT'],'sourceDateEpoch':int(e['SOURCE_DATE_EPOCH'])}
print(json.dumps([cs(e['TK_PKG'],e['TK_TAG'],e['TEE_K_DIGEST']), cs(e['TT_PKG'],e['TT_TAG'],e['TEE_T_DIGEST'])]))
")
    ;;
snp)
    DIGESTS="${SCRIPT_DIR}/snp-digests.env"
    [[ -f "${DIGESTS}" ]] || { echo "Missing ${DIGESTS} — write SNP_K_DIGEST/SNP_T_DIGEST/COMMIT from snp-build.sh output"; exit 1; }
    source "${DIGESTS}"
    : "${SNP_K_DIGEST:?not set in snp-digests.env}"; : "${SNP_T_DIGEST:?not set in snp-digests.env}"
    : "${COMMIT:?not set in snp-digests.env}"
    require_commit "${COMMIT}"
    SOURCE_DATE_EPOCH=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct "${COMMIT}")
    COMMIT_TIME=$(git -C "${REPO_ROOT}" log -1 --pretty=%cI "${COMMIT}")
    # SNP app digest is cross-cloud (role-keyed, no package/cloud); base is in base_images.
    NEW_ENTRIES=$(SNP_K_DIGEST="${SNP_K_DIGEST}" SNP_T_DIGEST="${SNP_T_DIGEST}" COMMIT="${COMMIT}" \
        COMMIT_TIME="${COMMIT_TIME}" SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python3 -c "
import json, os
e = os.environ
def snp(role, ver):
    return {'type':'sev-snp','role':role,'version':ver,'createTime':e['COMMIT_TIME'],
            'updateTime':e['COMMIT_TIME'],'sourceCommit':e['COMMIT'],'sourceDateEpoch':int(e['SOURCE_DATE_EPOCH'])}
print(json.dumps([snp('k',e['SNP_K_DIGEST']), snp('t',e['SNP_T_DIGEST'])]))
")
    ;;
*)
    echo "usage: $0 [cs|snp]" >&2; exit 1 ;;
esac

NEW_ENTRIES="${NEW_ENTRIES}" OUTPUT="${OUTPUT}" python3 -c "
import json, os
hist = json.load(open(os.environ['OUTPUT']))
hist.setdefault('base_images', [])
app = hist.setdefault('app_images', [])
existing = {x.get('version') for x in app}
added = 0
for entry in json.loads(os.environ['NEW_ENTRIES']):
    if entry['version'] not in existing:
        app.append(entry); added += 1
with open(os.environ['OUTPUT'], 'w') as f:
    json.dump(hist, f, indent=2); f.write('\n')
print(f'Added {added} app_images entries ({len(app)} total, {len(hist[\"base_images\"])} base_images)')
"
