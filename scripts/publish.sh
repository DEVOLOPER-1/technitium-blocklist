#!/usr/bin/env bash
# Publish dist/ as a single-commit orphan branch so the repo never accumulates
# 30 MB daily blobs. Skips the push when the published content hash is unchanged.
set -euo pipefail

OUT="${1:-dist}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

new_hash=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['content_sha256'])" "$OUT/build-report.json")
old_hash=""

if curl -fsSL --max-time 20 "https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/dist/build-report.json" -o /tmp/published-report.json 2>/dev/null; then
  old_hash=$(python3 -c "import json,sys; print(json.load(open('/tmp/published-report.json'))['content_sha256'])" 2>/dev/null || true)
fi

if [ -n "$old_hash" ] && [ "$old_hash" = "$new_hash" ]; then
  echo "content unchanged ($new_hash) - nothing to publish"
  exit 0
fi

cd "$OUT"
git init -q -b dist
git add -A
git -c user.name="blocklist-bot" \
    -c user.email="blocklist-bot@users.noreply.github.com" \
    commit -qm "build $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git push -f -q "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" dist
echo "published $new_hash"
