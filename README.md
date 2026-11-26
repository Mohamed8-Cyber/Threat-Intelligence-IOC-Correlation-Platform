# Threat Intelligence Aggregation and IOC Correlation Platform

A platform that collects indicators of compromise (IOCs) from feeds, partner bundles and analyst
reports, normalizes them, scores them, links related indicators, groups corroborated campaigns, and
exports the results.

**Status: MVP.** The design was reviewed by a council of advisors before it was built; the decisions
and the open limits are in [docs/COUNCIL_DECISIONS.md](docs/COUNCIL_DECISIONS.md). The architecture is
in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**All sample data is synthetic.** Domains use the reserved `.example` and `.test` names, addresses come
from the documentation ranges (RFC 5737), and the file hashes are digests of the sample files.

## Quick start

```bash
pip install -e ".[dev]"
tip demo                 # loads the sample feeds and analyst report, then prints clusters
tip serve                # dashboard and API at http://127.0.0.1:8000
pytest                   # 54 tests
```

`tip demo` writes `tip-demo.db` in the current directory and starts from a fresh database each time.

With Docker:

```bash
docker build -t tip-platform .
docker run -p 8000:8000 -e TIP_API_KEY=change-me -v tip-data:/data tip-platform
```

## What it does

- **Ingests** CSV, plain-text and STIX 2.1 feeds (local files or URLs), and free-text analyst reports.
  Defanged values such as `hxxps://evil[.]example` are restored before validation.
- **Normalizes** IPv4, IPv6, CIDR ranges, domains, URLs, email addresses, and MD5, SHA-1 and SHA-256
  hashes. Values that fail validation are counted and rejected, not stored.
- **Suppresses** allowlisted domains and their subdomains, so known-good infrastructure such as a
  vendor's update host does not reach the store.
- **Scores** each indicator with a triage rank that combines its sources and decays with age.
- **Correlates** indicators through structural facts (a URL's host, a subdomain's parent, an address
  inside a range) and through feed assertions that at least two sources agree on.
- **Exports** CSV, JSON, a plain blocklist, a STIX 2.1 indicator bundle, and an Excel workbook whose
  summary figures are live formulas.

## What the score means

The triage score is a **rank for analysts, not a probability** that an indicator is malicious. It
decides what to look at first. Do not compare it with a score from another system.

It is computed in three steps:

1. Each source contributes once, at its best `confidence × reliability`. A source that reports an
   indicator in several campaigns still counts once.
2. The contributions are combined by noisy-OR: `1 − Π(1 − contribution)`. Independent sources raise
   the score. The score never exceeds 1.0.
3. The result decays with a 30-day half-life from the most recent sighting.

Severity is a separate label, derived from the tags and the score. Related indicators, such as the
address in a passive-DNS row beside a malicious domain, get a zero-confidence context sighting. They
receive no score and are not counted as a source.

## How indicators are correlated

| Link origin | Example | Can form a cluster? |
|---|---|---|
| Structural | A URL served from a host; `a.b.example` under `b.example`; an address in `203.0.113.0/24` | Yes |
| Feed | A source says a domain resolves to an address; a payload was downloaded from a host | Only if at least two sources assert it, and the assertion is recent enough |
| Co-occurrence | Two indicators reported in the same campaign or report | **Never.** It is shown as a suggestion |

Two protections keep one shared address from merging unrelated campaigns:

- An indicator seen in two or more feed campaigns, or linked to more than ten others, is **shared
  infrastructure**. It is listed separately, with the reason, and kept out of the clusters.
- A campaign with more than 100 members is not expanded into pairwise links. The skip is counted in
  every ingest report.

## Command line

| Command | What it does |
|---|---|
| `tip demo` | Build a fresh demo database from the sample feeds and print the clusters |
| `tip feed list` | Show configured feeds, their reliability and last run |
| `tip feed run NAME` | Run one configured feed |
| `tip ingest FILE --source NAME --format text\|csv\|stix` | Ingest a local file |
| `tip report FILE --title "..."` | Extract indicators from an analyst report and group them under the title |
| `tip search [TEXT] [--type T] [--min-score X]` | Search indicators |
| `tip lookup TYPE VALUE` | Show one indicator as JSON |
| `tip correlate TYPE VALUE [--depth N]` | Show an indicator's neighbourhood and the reason for each link |
| `tip clusters [--min-weight X]` | List clusters and shared infrastructure |
| `tip export csv\|json\|stix\|blocklist\|xlsx --out FILE` | Export indicators |
| `tip serve [--host H] [--port P]` | Run the API and dashboard |

Global options: `--db PATH` and `--feeds PATH`.

## HTTP API

Read endpoints are open. Write endpoints require the `X-API-Key` header.

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /api/health` | open | Liveness, version, and whether writes need a key |
| `GET /api/stats` | open | Counts of indicators, sightings, links, clusters, feeds |
| `GET /api/feeds` | open | Configured feeds and their last run |
| `POST /api/feeds/{name}/run` | key | Run a configured feed |
| `POST /api/ingest` | key | Ingest text in `text`, `csv` or `stix` format |
| `POST /api/reports` | key | Extract indicators from analyst text |
| `GET /api/iocs?q=&type=&min_score=&limit=` | open | Search |
| `GET /api/iocs/lookup?type=&value=` | open | One indicator |
| `GET /api/correlate?type=&value=&depth=` | open | Neighbourhood and links |
| `GET /api/clusters?min_weight=&limit=` | open | Clusters and shared infrastructure |
| `GET /api/export/{csv,json,stix,blocklist,xlsx}?type=&min_score=` | open | Export |

Interactive documentation is served at `/docs`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TIP_DB_PATH` | `tip.db` | SQLite database |
| `TIP_FEEDS_FILE` | `data/samples/feeds.json` | Feed configuration |
| `TIP_API_KEY` | unset | Key for write endpoints. If unset, `tip serve` generates one for the run and prints it |
| `TIP_HALF_LIFE_DAYS` | `30` | Score half-life |
| `TIP_ALLOWLIST` | built-in list | Comma-separated domains to suppress, with their subdomains |
| `TIP_FETCH_TIMEOUT` | `15` | Seconds to wait for a remote feed |
| `TIP_MIN_SOURCES` | `2` | Independent sources needed before a feed link can form a cluster |
| `TIP_MAX_FAN_IN` | `10` | Links above which an indicator is shared infrastructure |
| `TIP_MAX_CAMPAIGN_MEMBERS` | `100` | Campaign size above which pairwise co-occurrence is skipped |
| `TIP_CLUSTER_MIN_WEIGHT` | `0.3` | Minimum decayed weight for a link to join a cluster |

## Demo results

From `tip demo` on a fresh database, using the sample feeds and the analyst report
(`out/demo-output.txt`):

| Feed | Accepted | Rejected | Suppressed | Notes |
|---|---:|---:|---:|---|
| passive-dns-sample (CSV) | 16 | 1 | 1 | `999.1.1.1` is not an address; `login.microsoft.com` is allowlisted |
| partner-stix-sample (STIX 2.1) | 9 | 1 | 0 | `process:name` is not a supported observable |
| community-blocklist (text) | 5 | 1 | 0 | `999.999.1.1` is not an address |
| analyst-report (free text) | 5 | 0 | 0 | Refanged from defanged prose |

Store after the run: **17 indicators, 49 sightings, 59 links, 4 campaigns.**

Three clusters form:

- **ShadowLoader**: 4 indicators, top triage 95%. A domain, its subdomain, a payload hash and a
  download URL.
- **PhishKit Ledger**, reported as `inc-2026-1022-payroll-beacon`: 5 indicators, top triage 94%.
  A phishing domain, its address, its URL, the address range, and the sender's mailbox.
- **CoinMiner-7**: 3 indicators, top triage 86%. A mining relay domain, its address, and a mirror.

One address, `198.51.100.23`, is seen in two campaigns (ShadowLoader and CoinMiner-7). It is listed as
shared infrastructure and is **not** used to merge the two campaigns.

## Performance

Measured with `scripts/bench_refresh.py` on synthetic data (`out/bench-output.txt`):

| Indicators | Campaign size | Ingest (s) | Full refresh (s) |
|---:|---:|---:|---:|
| 1,000 | 20 | 0.06 | 0.05 |
| 5,000 | 100 | 0.33 | 1.32 |
| 10,000 | 20 | 0.68 | 0.49 |
| 10,000 | 100 | 0.71 | 2.35 |

The refresh recomputes every derived link on each ingest. That is simple and correct at this size, and
it is the first limit to reach. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#performance) has the full
table and the plan.

## Limits

- The triage score is a rank. It is not calibrated against outcomes, and the platform has no
  ground-truth evaluation on real feeds.
- Two feeds that carry the same upstream data under different names count as two sources.
- Conflicting evidence has no resolution rule. Both sightings are kept and the malicious one is scored.
- Read endpoints are open and there is no TLS, rate limiting, or per-user audit trail. Put the service
  behind a reverse proxy before it leaves a trusted network.
- STIX relationships are not exported in this release. Indicator patterns are.
- A STIX pattern that lists a domain and an address together is read as asserting that they resolve to
  each other. That is the partner's claim, recorded with the partner's name.
- The derived links are recomputed in full on each ingest. This is measured and acceptable at the sizes
  above. It is not designed for millions of indicators.

## Tests

```bash
pytest
```

Fifty-four tests cover normalization, extraction, the three parsers, scoring, the pipeline rules
(shared infrastructure, corroboration, co-occurrence, context sightings, idempotent re-ingestion,
decay, the campaign cap), the demo command, and the API (key enforcement, search, lookup, every
export). The two central clustering rules, shared-infrastructure exclusion and two-source corroboration,
were checked by disabling each one on purpose; each rule's test failed when its rule was off.

## Layout

```
src/tip/            application package
  web/              dashboard (HTML, CSS, JavaScript; no build step)
data/samples/       synthetic feeds, partner bundle, blocklist, analyst report
tests/              pytest suite
scripts/            bench_refresh.py, a synthetic scale measurement
docs/               ARCHITECTURE.md, COUNCIL_DECISIONS.md, council/ (transcript and report)
out/                demo output, benchmark output, the Excel export
```
