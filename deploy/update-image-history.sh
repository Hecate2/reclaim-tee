#!/bin/bash
set -e

# =============================================================================
# Appends the V2 TEE image digests to deploy/image-history.json.
# Run after build-tees-v2.sh (+ deploy), from the same checkout.
#
# Source of truth is deploy/v2-digests.env, written by build-tees-v2.sh. That
# file is local-only and NOT committed; only image-history.json is. We record
# the digests plus the commit + SOURCE_DATE_EPOCH they were built from so
# verify.sh can rebuild the exact image from source. Skips digests already
# present, so re-runs are idempotent.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
OUTPUT="${SCRIPT_DIR}/image-history.json"
DIGESTS="${SCRIPT_DIR}/v2-digests.env"

[[ -f "${DIGESTS}" ]] || { echo "Missing ${DIGESTS} — run build-tees-v2.sh first"; exit 1; }
source "${DIGESTS}"
: "${TEE_K_TAG:?not set in v2-digests.env}"
: "${TEE_T_TAG:?not set in v2-digests.env}"
: "${TEE_K_DIGEST:?not set in v2-digests.env}"
: "${TEE_T_DIGEST:?not set in v2-digests.env}"
: "${COMMIT:?not set in v2-digests.env}"

# The recorded commit must exist in the repo, or verify.sh (which rebuilds it)
# can never reproduce the entry. Fails closed so we don't record an
# unverifiable image (e.g. built from an unmerged branch commit).
if ! git -C "${REPO_ROOT}" rev-parse --verify "${COMMIT}^{commit}" >/dev/null 2>&1; then
    echo "ERROR: COMMIT ${COMMIT} from v2-digests.env is not in this repo."
    echo "       Build + record from a committed (merged) commit so verify.sh can reproduce it."
    exit 1
fi

# Split "<registry>/<repo>/tee-k:<tag>" into package + tag. pkg.dev hosts carry
# no port, so the final colon always delimits the tag.
TK_PKG="${TEE_K_TAG%:*}"; TK_TAG="${TEE_K_TAG##*:}"
TT_PKG="${TEE_T_TAG%:*}"; TT_TAG="${TEE_T_TAG##*:}"

# Build metadata from the commit the image was actually built from (NOT HEAD).
SOURCE_DATE_EPOCH=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct "${COMMIT}")
COMMIT_TIME=$(git -C "${REPO_ROOT}" log -1 --pretty=%cI "${COMMIT}")

python3 -c "
import json, os

history = []
if os.path.exists('${OUTPUT}'):
    with open('${OUTPUT}') as f:
        history = json.load(f)

existing_versions = {e['version'] for e in history}

new_entries = [
    {
        'package': '${TK_PKG}',
        'tags': ['${TK_TAG}'],
        'version': '${TEE_K_DIGEST}',
        'createTime': '${COMMIT_TIME}',
        'updateTime': '${COMMIT_TIME}',
        'sourceCommit': '${COMMIT}',
        'sourceDateEpoch': ${SOURCE_DATE_EPOCH}
    },
    {
        'package': '${TT_PKG}',
        'tags': ['${TT_TAG}'],
        'version': '${TEE_T_DIGEST}',
        'createTime': '${COMMIT_TIME}',
        'updateTime': '${COMMIT_TIME}',
        'sourceCommit': '${COMMIT}',
        'sourceDateEpoch': ${SOURCE_DATE_EPOCH}
    }
]

added = 0
for entry in new_entries:
    if entry['version'] not in existing_versions:
        history.append(entry)
        added += 1

with open('${OUTPUT}', 'w') as f:
    json.dump(history, f, indent=2)
    f.write('\n')

print(f'Added {added} new entries ({len(history)} total)')
"

cat "${OUTPUT}"
