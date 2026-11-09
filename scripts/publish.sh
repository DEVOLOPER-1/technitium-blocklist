#!/usr/bin/env bash
# Publish the built list on two independent channels:
#
#   1. orphan branch `dist`  -> raw.githubusercontent.com/.../dist/<file>
#      simple, unauthenticated, but regular git blobs are capped at 100 MiB.
#   2. GitHub Release assets -> github.com/.../releases/download/<tag>/<file>
#      no 100 MiB cap (2 GiB per asset) and GitHub does not meter the bandwidth
#      used to deliver release assets, so this is the growth path.
#
# Both channels carry the same bytes, so either URL blocks identically.
# Skips everything when the content hash is unchanged.
set -euo pipefail

OUT="${1:-dist}"
TAG="${RELEASE_TAG:-blocklist}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

new_hash=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['content_sha256'])" "$OUT/build-report.json")
old_hash=""

if curl -fsSL --max-time 20 "https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/dist/build-report.json" -o /tmp/published-report.json 2>/dev/null; then
  old_hash=$(python3 -c "import json,sys; print(json.load(open('/tmp/published-report.json'))['content_sha256'])" 2>/dev/null || true)
fi

have_release=false
if gh release view "$TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  have_release=true
fi

if [ -n "$old_hash" ] && [ "$old_hash" = "$new_hash" ] && [ "$have_release" = true ]; then
  echo "content unchanged ($new_hash) and release exists - nothing to publish"
  exit 0
fi

cd "$OUT"
git init -q -b dist
git add -A
git -c user.name="blocklist-bot" \
    -c user.email="blocklist-bot@users.noreply.github.com" \
    commit -qm "build $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git push -f -q "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" dist
echo "pushed branch dist ($new_hash)"

# --- channel 2: release assets ----------------------------------------------
if [ "$have_release" = false ]; then
  gh release create "$TAG" \
    --repo "$GITHUB_REPOSITORY" \
    --target main \
    --title "Rolling blocklist builds" \
    --notes "Generated artefacts, replaced in place on every build."
  echo "created release $TAG"
fi

gh release upload "$TAG" \
  --repo "$GITHUB_REPOSITORY" \
  --clobber \
  technitium-blocklist.txt technitium-blocklist-compact.txt build-report.json
echo "uploaded release assets ($new_hash)"
