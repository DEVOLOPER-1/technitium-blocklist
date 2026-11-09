#!/usr/bin/env python3
"""Output invariants for the published blocklist.

Deliberately re-implements validation instead of importing the builder, so a
bug in the builder cannot make its own output look valid.

Run: python tests/test_output.py [outdir]
"""
import hashlib
import json
import os
import re
import sys

LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
FORBIDDEN = (" ", "\t", "*", "/", "^", "||", "0.0.0.0", "127.0.0.1", "::")
CRITICAL = {"com", "net", "org", "edu", "gov", "mil", "int", "arpa",
            "co.uk", "com.au", "co.jp", "co.il", "com.eg", "com.sa", "co.za", "com.br"}


def load(outdir, filename):
    path = os.path.join(outdir, filename)
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    header, body = [], []
    for line in text.split("\n"):
        if not line:
            continue
        (header if line.startswith("#") else body).append(line)
    return header, body, path


def main(outdir="dist"):
    report = json.load(open(os.path.join(outdir, "build-report.json"), encoding="utf-8"))
    full_h, full, full_path = load(outdir, "technitium-blocklist.txt")
    problems = []

    # --- full list ---------------------------------------------------------
    if len(full) < 50_000:
        problems.append("full list suspiciously small: %d" % len(full))
    if len(full) != len(set(full)):
        dup = len(full) - len(set(full))
        problems.append("%d duplicate lines in full list" % dup)
    if full != sorted(full):
        problems.append("full list is not lexicographically sorted")

    bad_syntax = [l for l in full if any(f in l for f in FORBIDDEN)]
    if bad_syntax:
        problems.append("%d lines contain forbidden tokens, e.g. %r" % (len(bad_syntax), bad_syntax[:3]))

    bad_labels = []
    for line in full:
        if len(line) > 253 or not all(LABEL_RE.match(lb) for lb in line.split(".")):
            bad_labels.append(line)
    if bad_labels:
        problems.append("%d invalid domain names, e.g. %r" % (len(bad_labels), bad_labels[:3]))

    critical = [l for l in full if l in CRITICAL]
    if critical:
        problems.append("catastrophic entries present: %r" % critical)

    # --- hash/report agreement --------------------------------------------
    body = "\n".join(full) + "\n"
    digest = hashlib.sha256(body.encode()).hexdigest()
    if digest != report["content_sha256"]:
        problems.append("content_sha256 mismatch (list was modified after the report)")
    if report["totals"]["unique"] != len(full):
        problems.append("report.totals.unique (%d) != actual (%d)"
                        % (report["totals"]["unique"], len(full)))

    # --- compact list ------------------------------------------------------
    compact_path = os.path.join(outdir, "technitium-blocklist-compact.txt")
    coverage_checked = 0
    if os.path.exists(compact_path):
        _, compact, _ = load(outdir, "technitium-blocklist-compact.txt")
        if len(compact) != len(set(compact)):
            problems.append("compact list has duplicates")
        if compact != sorted(compact):
            problems.append("compact list is not sorted")
        cset = set(compact)
        fset = set(full)
        extra = [c for c in compact if c not in fset]
        if extra:
            problems.append("compact has %d entries absent from full list" % len(extra))
        # every full entry must be covered by itself or a blocked parent
        uncovered = []
        for d in full:
            parts = d.split(".")
            if d in cset:
                coverage_checked += 1
                continue
            hit = False
            for i in range(1, len(parts)):
                if ".".join(parts[i:]) in cset:
                    hit = True
                    break
            if not hit:
                uncovered.append(d)
            coverage_checked += 1
        if uncovered:
            problems.append("compact drops %d domains with no blocked parent, e.g. %r"
                            % (len(uncovered), uncovered[:3]))

    # --- header ------------------------------------------------------------
    if not full_h:
        problems.append("missing header comment block")
    for line in full_h:
        if not line.startswith("#"):
            problems.append("header line does not start with '#': %r" % line)

    if problems:
        print("FAILED")
        for p in problems:
            print("  - " + p)
        return 1

    print("PASS  %d domains | %d compact | %d coverage checks | sha %s"
          % (len(full), len(compact) if os.path.exists(compact_path) else 0,
             coverage_checked, digest[:12]))
    print("      file: %s (%.1f MB)" % (full_path, os.path.getsize(full_path) / 1e6))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "dist"))
