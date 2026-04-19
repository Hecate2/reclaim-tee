#!/bin/bash
set -e

# =============================================================================
# Appends current image digests and timestamps to deploy/image-history.json.
# Run after each deploy to keep the history file current.
# Skips if the exact digest already exists in history.
# Records sourceCommit and sourceDateEpoch for reproducible verification.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"

source "${SCRIPT_DIR}/build.env" || { echo "Missing deploy/build.env"; exit 1; }
: "${REGISTRY:?REGISTRY not set in build.env}"

IMAGE_TAG="${IMAGE_TAG:-v2}"
OUTPUT="${SCRIPT_DIR}/image-history.json"

SOURCE_COMMIT=$(git -C "${REPO_ROOT}" log -1 --pretty=%H)
SOURCE_DATE_EPOCH=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct)

TK_JSON=$(gcloud container images list-tags ${REGISTRY}/tee-k --filter="tags:${IMAGE_TAG}" --format=json 2>/dev/null)
TT_JSON=$(gcloud container images list-tags ${REGISTRY}/tee-t --filter="tags:${IMAGE_TAG}" --format=json 2>/dev/null)

python3 -c "
import json, os

tk = json.loads('''${TK_JSON}''')[0]
tt = json.loads('''${TT_JSON}''')[0]

history = []
if os.path.exists('${OUTPUT}'):
    with open('${OUTPUT}') as f:
        history = json.load(f)

existing_versions = {e['version'] for e in history}

new_entries = [
    {
        'package': '${REGISTRY}/tee-k',
        'tags': tk['tags'],
        'version': tk['digest'],
        'createTime': tk['timestamp']['datetime'],
        'updateTime': tk['timestamp']['datetime'],
        'sourceCommit': '${SOURCE_COMMIT}',
        'sourceDateEpoch': ${SOURCE_DATE_EPOCH}
    },
    {
        'package': '${REGISTRY}/tee-t',
        'tags': tt['tags'],
        'version': tt['digest'],
        'createTime': tt['timestamp']['datetime'],
        'updateTime': tt['timestamp']['datetime'],
        'sourceCommit': '${SOURCE_COMMIT}',
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
