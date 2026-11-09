#!/usr/bin/env python3
"""Print a markdown summary of dist/build-report.json (used by the workflow)."""
import json
import os
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "dist/build-report.json"
if not os.path.exists(path):
    print("build failed before a report was written")
    raise SystemExit(0)

report = json.load(open(path, encoding="utf-8"))
totals = report["totals"]

print("### %d unique domains from %d sources" % (totals["unique"], totals["sources_used"]))
print()
print("- parsed: **%d**" % totals["domains_parsed"])
print("- exact duplicates removed: **%d**" % totals["exact_duplicates"])
print("- compact list: **%d** (-%d)" % (totals["compact"], totals["compact_saved"]))
print("- allowlist removed: %d" % totals["allowlist_removed"])
print("- safety drops: %d" % totals["safety_dropped"])
print("- sha256: `%s`" % report["content_sha256"][:16])
print()
print("| source | parsed | new unique | redundant |")
print("|---|---:|---:|---:|")
for src in report["sources"][:15]:
    pct = 100.0 * src["duplicates"] / max(src["domains_parsed"], 1)
    print("| %s | %d | %d | %.0f%% |" % (src["name"], src["domains_parsed"],
                                         src["new_unique"], pct))
