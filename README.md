# technitium-blocklist

[![build-blocklist](https://github.com/DEVOLOPER-1/technitium-blocklist/actions/workflows/build.yml/badge.svg)](https://github.com/DEVOLOPER-1/technitium-blocklist/actions/workflows/build.yml) [![pages-build-deployment](https://github.com/DEVOLOPER-1/technitium-blocklist/actions/workflows/pages/pages-build-deployment/badge.svg)](https://github.com/DEVOLOPER-1/technitium-blocklist/actions/workflows/pages/pages-build-deployment)

A single, deduplicated DNS blocklist compiled daily from 34 public lists, published in
three formats so the same data works on **Technitium**, **Pi-hole**, **AdGuard Home** and
**uBlock Origin**. Rebuilt every day at 03:17 UTC by GitHub Actions, verified before
publication, and served over two independent channels.

## Quick start

Pick the row for your resolver and paste that URL into its blocklist settings.

| Resolver | File | Why |
|---|---|---|
| **Technitium** | `technitium-blocklist-compact.txt` | recommended: same blocking, ~37 % fewer entries |
| **Pi-hole (FTL 5.22+)** | `technitium-blocklist-adblock.txt` | ABP rules cover subdomains |
| **AdGuard Home / AdGuard DNS** | `technitium-blocklist-adblock.txt` | ABP rules cover subdomains |
| **uBlock Origin** | `technitium-blocklist-adblock.txt` | browser extension, ABP is native |
| **Pi-hole before FTL 5.22** | `technitium-blocklist.txt` | no ABP parsing before March 2023 |
| Anything exact-match only | `technitium-blocklist.txt` | 1:1 copy of what upstream lists say |

Two channels carry identical bytes — use whichever is convenient:

```
# Release assets (recommended: no 100 MiB cap, bandwidth not metered)
https://github.com/DEVOLOPER-1/technitium-blocklist/releases/download/blocklist/technitium-blocklist-compact.txt
https://github.com/DEVOLOPER-1/technitium-blocklist/releases/download/blocklist/technitium-blocklist-adblock.txt
https://github.com/DEVOLOPER-1/technitium-blocklist/releases/download/blocklist/technitium-blocklist.txt

# dist branch (raw CDN, no redirect)
https://raw.githubusercontent.com/DEVOLOPER-1/technitium-blocklist/dist/technitium-blocklist-compact.txt
https://raw.githubusercontent.com/DEVOLOPER-1/technitium-blocklist/dist/technitium-blocklist-adblock.txt
https://raw.githubusercontent.com/DEVOLOPER-1/technitium-blocklist/dist/technitium-blocklist.txt
```

Each resolver refreshes on its own schedule — Technitium every 24 h (`Settings →
Blocking → Block List URLs`), Pi-hole on `pihole -g`, AdGuard Home on its configured
interval. No script has to run on the DNS host; the URL is enough.

## Which file, and why the formats differ

All three files block the same set of names. What differs is how each DNS engine
interprets a rule, and that decides whether a parent entry also covers its subdomains.

| Line in a list | Technitium | Pi-hole 5.22+ | AdGuard Home | uBlock Origin |
|---|---|---|---|---|
| `ads.example.com` | blocks it **and all subdomains** | blocks that host only | blocks that host only | n/a |
| <code>&#124;&#124;ads.example.com^</code> | blocks it and all subdomains | blocks it and all subdomains | blocks it and all subdomains | blocks it and all subdomains |
| <code>0.0.0.0 ads.example.com</code> | blocks it and all subdomains | blocks that host only | blocks that host only | n/a |

Sources: [AdGuard DNS rule syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
says of a bare domain rule: "blocks the `example.org` domain but not its subdomains";
Pi-hole's [domain database documentation](https://docs.pi-hole.net/database/domain-database/)
and the ABP parsing added in FTL 5.22 (March 2023) confirm the same split. Technitium differs because
`BlockListZoneManager.IsZoneBlocked` walks `GetParentZone`, so a blocked parent covers
every name beneath it.

That gives three files with three purposes:

* **`technitium-blocklist-compact.txt`** drops any entry whose parent is already listed.
  This is only equivalent on Technitium. On Pi-hole or AdGuard Home the same file would
  *lose* subdomain coverage, which is why it is not the recommended file there.
* **`technitium-blocklist-adblock.txt`** is that same compact set written as
  <code>&#124;&#124;domain^</code>. On ABP-aware engines one rule covers the whole subtree, so
  the file has fewer entries than the full list and still blocks at least as much.
* **`technitium-blocklist.txt`** is the honest 1:1 record: every unique domain exactly as
  upstream wrote it, with no assumption about parent matching. Use it for exact-match
  engines, for auditing, or when comparing against upstream counts.

Sizes at the time of writing (they drift daily):

| File | Format | Entries | Size |
|---|---|---:|---:|
| `technitium-blocklist.txt` | one domain per line | 4.63 M | 90 MB |
| `technitium-blocklist-compact.txt` | one domain per line, a parent covers its children | 2.91 M | 54 MB |
| `technitium-blocklist-adblock.txt` | <code>&#124;&#124;domain^</code> | 2.91 M | 63 MB |

Every file starts with a `#` comment header carrying the build time, source count and
entry count. Technitium, Pi-hole and AdGuard Home all treat `#` lines as comments.

## What gets blocked

Compiled from 34 enabled sources covering ads, tracking, malware, phishing, telemetry,
spam and abused TLDs. A typical build:

```
domains parsed            6,273,342
unique after dedupe       4,628,781     1,644,561 duplicates removed (26 %)
compact (parents subsume) 2,913,148     -1,715,633 (-37 %)
safety drops              1             (com.cn inside a malware feed)
```

`build-report.json`, published on the same channels, breaks that down per source: entries
parsed, unique contribution, duplicates, invalid lines. Some lists are largely redundant
by design — `hagezi-ultimate` overlaps the individual hagezi lists, which is what makes it
useful as insurance against a sub-list being renamed — and the report shows the overlap
instead of leaving it to guesswork. Sources that contribute nothing can be switched off
without changing the union.

## How the pipeline works

```
config/sources.yaml ──┐
config/allowlist.txt ─┼─> fetch ─> parse ─> normalise ─> guard ─> dedupe ─> compact ─> dist/
                      │                                    │
                      └──────────── verify <───────────────┘
.github/workflows/build.yml   daily 03:17 UTC · manual · on config change
```

1. **Fetch** — stdlib `urllib`, three retries with backoff, 120 s timeout per source.
2. **Parse** — the format is detected *per line*, so one file may mix syntaxes:
   * hosts (`0.0.0.0 domain`, `127.0.0.1 domain`, `::1 domain`, inline `#` comments)
   * plain domain lists (`domain.tld` per line)
   * adblock (`||domain^`, `||domain^$third-party`; `@@||domain^` becomes an allow rule)
   * cosmetic rules (`##`, `#@#`, `#?#`) are skipped rather than mangled into domains
3. **Normalise** — lowercase, strip trailing dot, `*.` → suffix, unicode → punycode,
   RFC-1035 label validation, length limits, drop IPs and hosts boilerplate
   (`localhost`, `ip6-localhost`, …). A stray `0.0.0.0.` that a sloppy upstream list glued
   onto a domain is recovered; a genuine numeric subdomain is left alone.
4. **Guard** — refuses to publish catastrophic entries (`com`, `net`, `org`, common
   public suffixes). Every drop is listed in `build-report.json`.
5. **Dedupe** — exact and global across all sources; first source wins and is recorded.
6. **Compact** — drop a domain when an ancestor is already blocked.
7. **Verify** — `tests/test_output.py` re-validates the output with an independent
   implementation: syntax, sort order, duplicates, hash agreement, catastrophic entries,
   and a full coverage proof that every domain in the full list is still covered by the
   compact list. A build that fails verification is never published.

If an enabled source cannot be fetched, the build **fails** rather than publishing a
silently shrunken list. A source may only be missing when marked `optional: true`.

## Sources

`config/sources.yaml` is the single source of truth.

| field | meaning |
|---|---|
| `name` | unique slug, `a-z0-9-` (appears in reports) |
| `url` | `https://` upstream list |
| `category` | grouping shown in the editor and the report |
| `enabled` | `false` parks a source without deleting it |
| `optional` | `true` lets the build continue when it 404s (use sparingly) |
| `note` | free-text remark, preserved by the editor |

Upstream lists retire without notice. These had to be re-pointed while this repository was
built; the table is worth checking first if a fork goes stale:

| was | now | reason |
|---|---|---|
| hagezi `tld-onlydomains.txt` | `wildcard/spam-tlds-onlydomains.txt` | renamed upstream |
| hagezi `nrd14-onlydomains.txt` | `hagezi/nrd` bands `nrd7` + `nrd14-8` | moved to its own repo, split into 7-day bands (~5.1 M domains, shipped disabled) |
| `GoodbyeAds-Spotify.txt` | `GoodbyeAds-Spotify-AdBlock.txt` | renamed upstream |
| blocklistproject `telemetry.txt` | — | retired upstream (404), parked disabled |
| `urlhaus.abuse.ch/downloads/hostfile/` | `malware-filter.gitlab.io/…/urlhaus-filter-hosts.txt` | abuse.ch removed public downloads (410 Gone) |

## Editing the list

Web editor: <https://devoloper-1.github.io/technitium-blocklist/>

* Toggle, rename, retarget, delete or add sources, then **Save to GitHub**. Saving
  touches `config/sources.yaml`, which triggers a rebuild automatically.
* **Run build now** dispatches the workflow and polls the run status.
* The *Build report* panel shows parsed / unique / redundant per source, and can disable
  every source that contributes nothing in one click.
* The **allowlist** tab edits `config/allowlist.txt` — domains that must never be blocked
  (children included), the clean way to kill a false positive without patching the merge.
* *Raw YAML* is an escape hatch; the editor checks a parse → generate → parse round-trip
  before it will save.

Saving needs a fine-grained PAT scoped to this repository with `Contents: Read and write`
and `Actions: Read and write`. It is held in the browser's `localStorage` and sent only to
`api.github.com`. Without a token the editor is read-only: download the YAML and commit it
by hand.

## Forking

1. Fork, then edit `config/sources.yaml` — or point the `OWNER`/`REPO` constants in
   `docs/index.html` at the fork so the editor follows it.
2. Enable Pages for the fork: *Settings → Pages → main → /docs*.
3. Nothing else: the workflow uses the built-in `GITHUB_TOKEN`, no secrets to add.

## Local use

```bash
pip install pyyaml==6.0.2

python3 tests/test_parser.py                              # parser unit tests
python3 scripts/build_blocklist.py --outdir dist          # full build (network)
python3 tests/test_output.py dist                         # output invariants

# build from pre-downloaded files named <source-name>.txt instead of the network
python3 scripts/build_blocklist.py --raw-dir /path/to/raw --outdir dist
```

Exit codes: `0` ok, `2` config error, `3` fetch/parse failure, `4` below `--min-domains`
(default 50 000, a guard against upstream breakage).

## Repository layout

```
config/sources.yaml         source catalogue (edited by the web UI)
config/allowlist.txt        never-block list
scripts/build_blocklist.py  build pipeline
scripts/publish.sh          publishes dist branch + release assets
scripts/summary.py          Actions job summary
tests/test_parser.py        parsing/normalisation unit tests
tests/test_output.py        published-list invariants (independent implementation)
docs/index.html             GitHub Pages editor
.github/workflows/build.yml daily build
```

Artefacts are never committed to `main`. `publish.sh` force-pushes a single-commit orphan
branch (`dist`) and uploads release assets, so the repository does not accumulate ~150 MB
of daily blobs.

## Limits and caveats

* **Memory.** Technitium keeps its block-list zone in memory; 4.6 M entries costs roughly
  1 GB of RAM and ~30 s of load. Prefer the compact file. Dropping
  `blocklistproject-malware` alone removes ~2.3 M entries.
* **Whole-TLD blocks.** The spam-TLD list blocks entire TLDs by design. It is the first
  thing to suspect if a legitimate site breaks.
* **Newly-registered domains.** NRD feeds are high false-positive by nature, so they ship
  disabled; enable them in `config/sources.yaml` if that trade-off is acceptable.
* **Do not move these files to Git LFS.** LFS replaces a file with a ~130-byte pointer, so
  `raw.githubusercontent.com` would serve the pointer instead of the list: a resolver
  downloads it, parses zero domains, and empties its block zone. LFS is also metered per
  push, and every rebuild would count the whole file against the free 10 GiB quota again.
  GitHub's own guidance for distributing large files is release assets, which is what this
  repository uses.
* **Upstream breakage is normal.** Lists move, get renamed, or vanish. The build fails
  loudly instead of shipping a smaller list, so a red run usually means one upstream URL
  needs updating rather than a bug here.
* Every upstream list is a third-party work under its own licence. This repository only
  merges and normalises them.
