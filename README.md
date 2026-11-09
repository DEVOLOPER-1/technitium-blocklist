# technitium-blocklist

[![build-blocklist](https://github.com/DEVOLOPER-1/technitium-blocklist/actions/workflows/build.yml/badge.svg)](https://github.com/DEVOLOPER-1/technitium-blocklist/actions/workflows/build.yml) [![pages-build-deployment](https://github.com/DEVOLOPER-1/technitium-blocklist/actions/workflows/pages/pages-build-deployment/badge.svg)](https://github.com/DEVOLOPER-1/technitium-blocklist/actions/workflows/pages/pages-build-deployment)

One deduplicated, normalised DNS blocklist for **Technitium DNS Server**, rebuilt
daily from 34 enabled upstream lists by GitHub Actions.

```
https://raw.githubusercontent.com/DEVOLOPER-1/technitium-blocklist/dist/technitium-blocklist.txt
```

Paste that URL into *Settings → Blocking → Block List URLs*. Technitium re-downloads
it every 24 h on its own; no script is needed on the server.

A second file, `technitium-blocklist-compact.txt`, is the same list with subdomains
already covered by a blocked parent removed. Technitium blocks the queried name *and
all of its parents* (`BlockListZoneManager.IsZoneBlocked` walks `GetParentZone`), so
the compact file blocks exactly the same names with 20–30 % fewer entries. Use it if
memory matters; use the full file if you want a 1:1 record of upstream entries.

## Why merge at all

Every list is downloaded, parsed, normalised and deduplicated into a single file.
Technitium gets one HTTP fetch instead of 35, one parse instead of 35, and one
dictionary instead of 35 — the block-list zone is a flat `Dictionary<string,...>`
plus a parent walk per query, so overlapping lists only cost memory and load time.

## Findings from the first build

Your 36 URLs went in and came out as one file of 4,628,759 domains from 6,273,319
parsed entries — **1,644,560 duplicates (26 %) removed**. Three things worth knowing:

* **Three sources were dead** and are now pointed at their current locations
  (`tld`, `nrd14`, `GoodbyeAds-Spotify` renamed; blocklistproject `telemetry.txt` and
  the urlhaus download endpoint retired upstream). Details in the table below.
* **Three sources contribute nothing at all** once merged — `hagezi-fake`, `spam404`,
  `phishing-army-extended` are 100 % covered by the others. The editor can disable them
  in one click; the union does not change.
* **`hagezi-ultimate` is 91 % redundant** here (263,990 parsed, 22,332 new) because the
  individual hagezi lists are already enabled. Keeping it is fine — it is the cheapest
  insurance against a sub-list being renamed again — but it is not free of overlap.
* One upstream entry, `com.cn` in `cyberhost-malware`, was refused by the safety guard:
  blocking a whole country's ccTLD is never the intent of a malware feed.

## How the pipeline works

```
config/sources.yaml ──┐
config/allowlist.txt ─┼─> fetch ─> parse ─> normalise ─> guard ─> dedupe ─> compact ─> dist/
.github/workflows/build.yml (daily 03:17 UTC + manual + on config change)
```

1. **Fetch** — stdlib `urllib`, 3 retries with backoff, 120 s timeout.
2. **Parse** — format is detected *per line*, so one file may mix syntaxes:
   * hosts (`0.0.0.0 domain`, `127.0.0.1 domain`, `::1 domain`, inline `#` comments)
   * plain domain lists (`domain.tld` per line)
   * adblock (`||domain^`, `||domain^$third-party`; `@@||domain^` becomes an allow rule)
   * cosmetic/browser rules (`##`, `#@#`, `#?#`) are skipped, not mangled into domains
3. **Normalise** — lowercase, strip trailing dot, `*.` → suffix, unicode → punycode,
   RFC-1035 label validation, length limits, drop IPs and hosts boilerplate
   (`localhost`, `ip6-localhost`, …).
4. **Guard** — refuses to publish catastrophic entries (`com`, `net`, `org`, common
   public suffixes). Every drop is listed in `build-report.json`.
5. **Dedupe** — exact, global across all sources, first source wins (recorded in the report).
6. **Compact** — drop a domain when an ancestor is already blocked.
7. **Verify** — `tests/test_output.py` re-validates the result with an independent
   implementation and refuses to publish if anything is off.

If any enabled source fails to download the build **fails** instead of publishing a
silently shrunken list. Mark a source `optional: true` to accept its absence.

## What the output looks like

```
# Technitium merged blocklist
# full build: 2026-11-09T18:07:51Z
# Sources: 34 enabled / 37 configured | 6273319 domains parsed
# This file: 4628759 domains
# Generated file - edit config/sources.yaml, not this list.
# Format: one domain per line. Upstream lists keep their own licences.
0--0--makepipelinespringpipeline0-3210zyxwvu.buildyourdata.com
0--0-06-33362599-server.buildyourdata.com
...
```

Technitium skips `#` and `!` lines and accepts a bare domain per line
(`BlockListZoneManager.ReadListFile`), so this parses natively — no conversion needed
on your side.

### Size, and which file to use

| file | domains | size | use |
|---|---:|---:|---|
| `technitium-blocklist-compact.txt` | ~2.9 M | ~54 MB | **recommended** for Technitium |
| `technitium-blocklist.txt` | ~4.6 M | ~90 MB | full record / audit |

Both block identically. The block-list zone is a `Dictionary<string,…>` in memory, so
4.6 M entries costs roughly 1 GB of RAM and ~30 s of load time; 2.9 M costs ~35 % less.
GitHub also hard-refuses any single file above 100 MB, so if the full list keeps growing
the compact file is the one to keep publishing — switch it off with `output.compact: false`
only if you need the 1:1 record.

If even the compact file is too heavy, disable `blocklistproject-malware` in the editor:
it alone contributes ~2.3 M unique domains.

## Editing the list

Open the editor (GitHub Pages): <https://devoloper-1.github.io/technitium-blocklist/>

* Toggle, rename, retarget, delete or add sources, then **Save to GitHub**.
  Saving touches `config/sources.yaml`, which triggers a rebuild automatically.
* **Run build now** dispatches the workflow and polls the run status.
* The *Build report* panel shows parsed / unique / redundant per source, so lists that
  contribute nothing are visible and can be switched off.
* The **allowlist** tab edits `config/allowlist.txt` — domains you never want blocked
  (subdomains included), the clean way to kill a false positive.
* *Raw YAML* is an escape hatch; the editor verifies a parse → generate → parse
  round-trip before it will save.

Saving needs a fine-grained PAT (this repo only) with `Contents: Read and write` and
`Actions: Read and write`. It is kept in the browser's localStorage and sent only to
`api.github.com`. Without a token the editor still works read-only: download the YAML
and commit it yourself.

## Source catalogue

`config/sources.yaml` is the single source of truth. Fields:

| field | meaning |
|---|---|
| `name` | unique slug, `a-z0-9-` (appears in reports) |
| `url` | `https://` upstream list |
| `category` | grouping shown in the editor |
| `enabled` | `false` parks a source without deleting it |
| `optional` | `true` lets the build continue when it 404s (use sparingly) |
| `note` | free-text remark, preserved by the editor |

Upstream lists retire without notice; these were replaced during setup:

| was | now | reason |
|---|---|---|
| hagezi `tld-onlydomains.txt` | `wildcard/spam-tlds-onlydomains.txt` | renamed upstream |
| hagezi `nrd14-onlydomains.txt` | `hagezi/nrd` bands `nrd7` + `nrd14-8` | moved to its own repo, split into 7-day bands; ~5.1 M domains, parked disabled |
| `GoodbyeAds-Spotify.txt` | `GoodbyeAds-Spotify-AdBlock.txt` | renamed upstream |
| blocklistproject `telemetry.txt` | — | retired upstream (404); parked disabled |
| `urlhaus.abuse.ch/downloads/hostfile/` | `malware-filter.gitlab.io/…/urlhaus-filter-hosts.txt` | abuse.ch removed public downloads (410 Gone) |

## Local use

```bash
pip install pyyaml==6.0.2

python3 tests/test_parser.py                              # parser unit tests
python3 scripts/build_blocklist.py --outdir dist          # full build (network)
python3 tests/test_output.py dist                         # output invariants

# use pre-downloaded files named <source-name>.txt instead of the network
python3 scripts/build_blocklist.py --raw-dir /path/to/raw --outdir dist
```

Exit codes: `0` ok, `2` config error, `3` fetch/parse failure, `4` below
`--min-domains` (default 50 000, a guard against upstream breakage).

## Repository layout

```
config/sources.yaml        source catalogue (edited by the web UI)
config/allowlist.txt       never-block list
scripts/build_blocklist.py build pipeline
scripts/publish.sh         publishes dist/ as a single-commit orphan branch
scripts/summary.py         Actions job summary
tests/test_parser.py       parsing/normalisation unit tests
tests/test_output.py       published-list invariants
docs/index.html            GitHub Pages editor
.github/workflows/build.yml daily build
```

The `dist` branch is force-pushed with a single commit on every content change, so the
repository never accumulates 30 MB daily blobs. `main` holds only sources and code.

## Caveats

* Blocking a TLD (the spam-TLD list) blocks *every* domain under it. That is the
  intent of that list, but it is the first thing to suspect if a site breaks.
* Newly-registered-domain feeds are high false-positive by nature; they are disabled
  in `config/sources.yaml` and can be switched on from the editor.
* Upstream lists are third-party works, each under its own licence. This repo only
  merges them.
