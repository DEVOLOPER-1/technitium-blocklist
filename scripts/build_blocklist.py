#!/usr/bin/env python3
"""Build one deduplicated, normalised blocklist for a Technitium DNS server.

Pipeline: fetch -> parse -> normalise -> drop hazards -> dedupe -> (compact) -> emit

Outputs written to --outdir:
  technitium-blocklist.txt          exact dedupe (every unique domain)
  technitium-blocklist-compact.txt  parent-subsumed; identical blocking behaviour
  build-report.json                 per-source statistics + content hash

Technitium semantics this relies on (DnsServerCore/Dns/ZoneManagers/
BlockListZoneManager.cs, method IsZoneBlocked): a queried name is blocked when
itself *or any parent* is present in the list. Hence "a.b.c" is redundant when
"b.c" is present, and a blocked TLD blocks every name under it.

Exit codes: 0 success, 2 configuration error, 3 fetch/parse error, 4 output
failed the sanity floor.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("error: PyYAML is required (pip install pyyaml)")

UA = "technitium-blocklist-builder/1.0 (+https://github.com/)"
MAX_NAME_LEN = 253
LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
ABP_RE = re.compile(r"^\|\|([^/^$|]+)(?:\^(.*))?$")
COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#")
SKIP_OPTIONS = ("badfilter", "domain=", "denyallow", "removeparam", "replace", "redirect")

# Names that must never enter a blocklist: RFC 6761 special-use + hosts boilerplate.
NEVER_BLOCK = {
    "localhost", "localhost.localdomain", "local", "localdomain", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
    "ip6-allrouters", "ip6-allhosts", "invalid", "test", "example", "onion",
}

# Guard against a catastrophic single entry wiping out the internet. Only
# applied when output.safety_guard is true; every drop is reported.
CRITICAL_SUFFIXES = {
    "com", "net", "org", "edu", "gov", "mil", "int", "arpa",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp",
    "co.il", "com.eg", "com.sa", "co.za", "com.br", "co.in", "com.cn", "com.tr",
    "co.kr", "com.mx", "com.ar", "com.tw", "com.hk", "com.sg", "co.nz", "com.ua",
    "co.id", "com.my", "com.ph", "com.vn", "co.th", "com.pk", "co.ae",
}


# --------------------------------------------------------------------------- #
# normalisation
# --------------------------------------------------------------------------- #
def looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_domain(raw: str):
    """Return (domain, None) or (None, reason). Never raises."""
    d = raw.strip().strip(".").lower()
    if not d:
        return None, "empty"
    if d.startswith("*."):
        d = d[2:]
    elif d.startswith("*"):
        return None, "wildcard-syntax"
    if d.startswith("."):
        d = d[1:]
    if not d:
        return None, "empty"
    if "/" in d or ":" in d:
        return None, "path-or-port"
    if looks_like_ip(d):
        return None, "ip"
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            return None, "idna"
    if len(d) > MAX_NAME_LEN:
        return None, "too-long"
    if d in NEVER_BLOCK:
        return None, "local-name"
    for label in d.split("."):
        if not LABEL_RE.match(label):
            return None, "bad-label"
    return d, None


def parents(domain: str):
    """Yield every strict ancestor: a.b.c -> b.c, c"""
    parts = domain.split(".")
    for i in range(1, len(parts)):
        yield ".".join(parts[i:])


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def parse_list(text: str):
    """Parse hosts / plain-domain / adblock text into (domains, exceptions, stats)."""
    stats: Counter = Counter()
    domains: list[str] = []
    exceptions: list[str] = []

    if text.startswith("\ufeff"):
        text = text[1:]
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            stats["blank"] += 1
            continue
        if line[0] in "#!;[" :
            stats["comment"] += 1
            continue

        # --- adblock syntax ------------------------------------------------
        if line.startswith("@@||"):
            m = ABP_RE.match(line[2:])
            if m:
                d, reason = normalize_domain(m.group(1))
                if d:
                    exceptions.append(d)
                else:
                    stats["invalid:" + reason] += 1
            else:
                stats["abp-unparsed"] += 1
            continue
        if line.startswith("||"):
            m = ABP_RE.match(line)
            if not m:
                stats["abp-unparsed"] += 1
                continue
            options = (m.group(2) or "").lower()
            if options.startswith("$") and any(k in options for k in SKIP_OPTIONS):
                stats["abp-skipped-option"] += 1
                continue
            d, reason = normalize_domain(m.group(1))
            if d:
                domains.append(d)
            else:
                stats["invalid:" + reason] += 1
            continue
        if any(mark in line for mark in COSMETIC_MARKERS):
            stats["cosmetic"] += 1
            continue

        # --- hosts / plain domain ------------------------------------------
        tokens = line.split()
        if not tokens:
            stats["blank"] += 1
            continue
        if looks_like_ip(tokens[0]):
            candidates = tokens[1:]
            if not candidates:
                stats["invalid:ip"] += 1
        elif len(tokens) == 1:
            candidates = tokens
        else:
            # "domain # trailing comment" -> domain; anything else is noise.
            candidates = tokens[:1]
            stats["multi-token"] += 1
        for cand in candidates:
            if cand.startswith("#"):
                break
            if looks_like_ip(cand):
                stats["invalid:ip"] += 1
                continue
            d, reason = normalize_domain(cand)
            if d:
                domains.append(d)
            else:
                stats["invalid:" + reason] += 1
    return domains, exceptions, stats


# --------------------------------------------------------------------------- #
# fetching
# --------------------------------------------------------------------------- #
def fetch(url: str, timeout: int = 120, retries: int = 3) -> bytes:
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            req = Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
            with urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if len(data) < 64:
                raise ValueError("implausibly small body (%d bytes)" % len(data))
            return data
        except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(str(last_error))


def decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    if not isinstance(cfg, dict):
        raise SystemExit("config error: top level must be a mapping")
    sources = cfg.get("sources")
    if not isinstance(sources, list) or not sources:
        raise SystemExit("config error: 'sources' must be a non-empty list")

    seen = set()
    for src in sources:
        if not isinstance(src, dict):
            raise SystemExit("config error: each source must be a mapping")
        name = src.get("name")
        url = src.get("url")
        if not isinstance(name, str) or not SLUG_RE.match(name):
            raise SystemExit("config error: bad source name %r (a-z, 0-9, -)" % (name,))
        if name in seen:
            raise SystemExit("config error: duplicate source name %r" % (name,))
        seen.add(name)
        if not isinstance(url, str) or not url.startswith("https://"):
            raise SystemExit("config error: %s needs an https:// url" % name)
        src.setdefault("enabled", True)
        src.setdefault("optional", False)
        src.setdefault("category", "misc")
    return cfg


def load_allowlist(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # tolerate "domain # note"
            line = line.split("#", 1)[0].strip()
            d, _ = normalize_domain(line)
            if d:
                out.append(d)
    return out


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config/sources.yaml")
    ap.add_argument("--allowlist", default="config/allowlist.txt")
    ap.add_argument("--outdir", default="dist")
    ap.add_argument("--raw-dir", help="use pre-downloaded <name>.txt files instead of network")
    ap.add_argument("--min-domains", type=int, default=50_000,
                    help="fail if the merged list is smaller than this (default 50000)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    out_cfg = cfg.get("output") or {}
    title = out_cfg.get("title") or "Technitium merged blocklist"
    full_name = out_cfg.get("filename") or "technitium-blocklist.txt"
    compact_name = out_cfg.get("compact_filename") or "technitium-blocklist-compact.txt"
    do_sort = bool(out_cfg.get("sort", True))
    do_compact = bool(out_cfg.get("compact", True))
    safety_guard = bool(out_cfg.get("safety_guard", True))

    sources = cfg["sources"]
    enabled = [s for s in sources if s.get("enabled", True)]
    if not enabled:
        raise SystemExit("config error: no enabled sources")

    os.makedirs(args.outdir, exist_ok=True)

    # ---- fetch + parse ---------------------------------------------------
    parsed_per_source: list[dict] = []
    seen: dict[str, str] = {}
    exceptions: set[str] = set()
    dropped_dangerous: list[dict] = []
    failures: list[str] = []

    for src in enabled:
        name, url = src["name"], src["url"]
        t0 = time.time()
        try:
            if args.raw_dir:
                local = os.path.join(args.raw_dir, name + ".txt")
                if not os.path.exists(local):
                    raise RuntimeError("missing local file %s" % local)
                data = open(local, "rb").read()
            else:
                data = fetch(url)
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            msg = "%-32s %s" % (name, exc)
            if src.get("optional"):
                if not args.quiet:
                    print("WARN  optional source failed: " + msg, file=sys.stderr)
                continue
            failures.append(msg)
            continue

        domains, source_exceptions, stats = parse_list(decode(data))
        exceptions.update(source_exceptions)

        new = dup = guarded = 0
        for d in domains:
            if safety_guard and d in CRITICAL_SUFFIXES:
                guarded += 1
                dropped_dangerous.append({"domain": d, "source": name})
                continue
            if d in seen:
                dup += 1
            else:
                seen[d] = name
                new += 1

        parsed_per_source.append({
            "name": name,
            "url": url,
            "category": src.get("category", "misc"),
            "bytes": len(data),
            "domains_parsed": len(domains),
            "new_unique": new,
            "duplicates": dup,
            "safety_dropped": guarded,
            "exceptions": len(source_exceptions),
            "invalid": {k.split(":", 1)[1]: v for k, v in stats.items() if k.startswith("invalid:")},
            "skipped": {k: v for k, v in stats.items()
                        if not k.startswith("invalid:") and k not in ("blank", "comment")},
            "seconds": round(time.time() - t0, 1),
        })
        if not args.quiet:
            print("  %-32s %8d parsed  %8d new  %7d dup  %5.1fs"
                  % (name, len(domains), new, dup, time.time() - t0))

    if failures:
        print("\nERROR: %d enabled source(s) could not be fetched:" % len(failures), file=sys.stderr)
        for f in failures:
            print("  " + f, file=sys.stderr)
        print("Refusing to publish a shrunken list. Mark the source optional: true "
              "if it is genuinely dead.", file=sys.stderr)
        return 3

    # ---- allowlist -------------------------------------------------------
    allow = load_allowlist(args.allowlist)
    allow_removed = 0
    if allow:
        allow_set = set(allow)
        for d in list(seen):
            if d in allow_set or any(p in allow_set for p in parents(d)):
                del seen[d]
                allow_removed += 1
    if exceptions:
        for d in list(seen):
            if d in exceptions or any(p in exceptions for p in parents(d)):
                del seen[d]

    total_unique = len(seen)
    if total_unique < args.min_domains:
        print("ERROR: only %d unique domains (< --min-domains %d). "
              "Upstream lists are probably broken." % (total_unique, args.min_domains),
              file=sys.stderr)
        return 4

    # ---- order + compaction ---------------------------------------------
    full = sorted(seen) if do_sort else list(seen)
    full_set = set(full)
    compact = [d for d in full if not any(p in full_set for p in parents(d))] if do_compact else []

    # ---- emit ------------------------------------------------------------
    stamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    parsed_total = sum(p["domains_parsed"] for p in parsed_per_source)

    def header(kind: str, count: int) -> list[str]:
        lines = [
            "# %s" % title,
            "# %s build: %s" % (kind, stamp),
            "# Sources: %d enabled / %d configured | %d domains parsed" %
            (len(parsed_per_source), len(sources), parsed_total),
            "# This file: %d domains" % count,
        ]
        if kind == "compact":
            lines.append("# Subdomains already covered by a blocked parent are omitted, which")
            lines.append("# Technitium treats identically (blocked zone match walks parents).")
        lines.append("# Generated file - edit config/sources.yaml, not this list.")
        lines.append("# Format: one domain per line. Upstream lists keep their own licences.")
        return lines

    body = "\n".join(full) + "\n"
    digest = hashlib.sha256(body.encode()).hexdigest()

    with open(os.path.join(args.outdir, full_name), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(header("full", len(full))) + "\n" + body)

    if compact:
        with open(os.path.join(args.outdir, compact_name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(header("compact", len(compact))) + "\n" + "\n".join(compact) + "\n")

    report = {
        "generated_at": stamp,
        "content_sha256": digest,
        "totals": {
            "sources_configured": len(sources),
            "sources_used": len(parsed_per_source),
            "domains_parsed": parsed_total,
            "unique": total_unique,
            "exact_duplicates": parsed_total - total_unique - allow_removed,
            "allowlist_removed": allow_removed,
            "safety_dropped": len(dropped_dangerous),
            "compact": len(compact),
            "compact_saved": total_unique - len(compact),
        },
        "sources": sorted(parsed_per_source,
                          key=lambda p: p["new_unique"], reverse=True),
        "dropped_dangerous": dropped_dangerous[:200],
    }
    with open(os.path.join(args.outdir, "build-report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, ensure_ascii=False)
        fh.write("\n")

    if not args.quiet:
        print("\nunique domains      : %d" % total_unique)
        print("compact (parent-sub): %d  (-%d, -%.1f%%)"
              % (len(compact), total_unique - len(compact),
                 100.0 * (total_unique - len(compact)) / max(total_unique, 1)))
        print("allowlist removed   : %d" % allow_removed)
        print("safety drops        : %d" % len(dropped_dangerous))
        print("output              : %s/%s" % (args.outdir, full_name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
