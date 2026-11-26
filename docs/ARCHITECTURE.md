# Architecture

This document describes how the platform is built and why. The decisions that came out of design
review are listed in [COUNCIL_DECISIONS.md](COUNCIL_DECISIONS.md).

## Components

```
 feeds.json ─┐                 ┌── CSV / text / STIX 2.1 parsers
 local files ┼─► Aggregator ───┤
 analyst text┘   (allowlist,   └── free-text extraction (refang, masking)
                  sightings)
                      │
                      ▼
                 SQLite store ◄──── Correlator (structural + co-occurrence links, clusters)
                      │
                      ▼
 TIPService ─► CLI (`tip`)  ─► HTTP API (FastAPI) ─► dashboard (static HTML/JS)
                      │
                      └─► exporters: CSV, JSON, blocklist, STIX 2.1 indicators, xlsx
```

| Module | Responsibility |
|---|---|
| `models.py` | `IOCType`, `Observation`, `ParseResult`, campaign keys, timestamps |
| `normalize.py` | Refang and defang, type detection, validation, host extraction, allowlist matching |
| `extract.py` | Pulls indicators out of free text. Masks longer matches first so a URL's host is not also read as a domain |
| `feeds/` | Feed specification and the three parsers |
| `aggregator.py` | The ingestion pipeline. Applies the allowlist, stores sightings, records feed runs |
| `storage.py` | SQLite schema, sighting upserts, per-indicator summary, link store |
| `scoring.py` | Noisy-OR, exponential decay, severity labels |
| `correlation.py` | Derived links, neighbourhood walk, cluster and shared-infrastructure computation |
| `service.py` | Application facade used by both the CLI and the API. Holds one lock around the store |
| `exporters.py` | The five export formats |
| `api.py`, `cli.py` | Transport layers. Neither contains business logic |

## Data model

| Table | Holds | Key |
|---|---|---|
| `iocs` | One row per indicator, with its summary: triage score, first and last seen, source count, merged tags, campaigns | looked up by (type, value) |
| `sightings` | One row per (indicator, source, campaign): confidence, source reliability, time seen | (indicator, source, campaign) |
| `links` | Directed relations between indicators, each with an origin, a source name, a weight and, for feed links, a timestamp | (src, dst, relation, origin, source) |
| `feed_runs` | Status and counters of the last run of each configured feed | feed name |

Upserts keep re-ingestion idempotent. A sighting that repeats an earlier one updates the row
instead of adding one, so running the same feed twice changes nothing.

## Ingestion

1. A payload is read from a local path or fetched over HTTP, with a size cap of 50 MB.
2. The parser returns observations and a count of rejected rows. A parser never raises on a bad
   row; it counts it.
3. For each observation, the allowlist is checked against the host (domain, URL host, email
   domain, or address). Allowlisted hosts and their subdomains are suppressed and counted.
4. The sighting is stored and the indicator's summary is recomputed.
5. Related indicators from the same row (for example the address in a passive DNS row) are stored
   as **context sightings with confidence 0**, linked to the observation by a feed link. They
   gain no score and do not count as a source of their own.
6. The whole ingest runs in one transaction. A failure rolls it back.
7. The correlator then recomputes derived links (see below).

## Scoring

For each indicator, every source contributes once, at its best `confidence × reliability`. The
contributions are combined by noisy-OR:

    score = 1 − Π (1 − contribution_source)

Two properties follow from this. A source that repeats itself does not raise the score: only its best
sighting counts, however many campaigns it reports the indicator in. Several sources do raise it.
The score is never above 1.0. Two feeds that carry the same upstream data under different names
still count as two sources; that is an open risk, listed in [COUNCIL_DECISIONS.md](COUNCIL_DECISIONS.md).

The score is then decayed with a half-life of 30 days (`TIP_HALF_LIFE_DAYS`), measured from the
most recent sighting. Scores only fall with age, so a search filter on the stored score is an
upper bound and is re-checked against the decayed value.

**The score is a triage rank.** It orders what an analyst should look at first. It is not the
probability that an indicator is malicious, and it should not be compared with a score from
another system.

Severity is a label, not a second score. It is `critical` when the score is at least 0.8 and a
high-risk tag is present (for example `c2`, `stealer`, `ransomware`). It is `high` for any
high-risk tag or a score of at least 0.7. It is `medium` for a medium-risk tag or a score of at
least 0.4, and `low` otherwise.

## Correlation

Links come from three origins, kept apart on purpose:

| Origin | Created by | Eligible to form clusters |
|---|---|---|
| `structural` | Values alone: URL host, parent domain, email domain, address inside a CIDR range | Yes, weight 1.0 |
| `feed` | A source asserting a relation, such as `resolves_to` or `downloaded_from` | Only when at least `TIP_MIN_SOURCES` (default 2) distinct sources assert it, and its decayed weight is at least 0.3 |
| `cooccurrence` | Two indicators reported in the same campaign or report | **Never** |

Co-occurrence is shown to an analyst as a suggestion. Two indicators that appear in the same
report are not thereby the same campaign.

**Clusters** are connected components over the eligible links, found with union-find. Before the
components are formed, two kinds of indicator are removed from the graph:

- **Shared infrastructure**: an indicator reported in two or more distinct feed campaigns, or
  linked to more than `TIP_MAX_FAN_IN` (default 10) others. Removing it stops one shared address
  from merging unrelated campaigns. These are listed separately with the reasons they were
  removed.
- **Oversized campaigns**: a campaign with more than `max_campaign_members` (default 100)
  indicators is not expanded into pairwise co-occurrence links. The count is returned with every
  ingest report, so it is visible rather than silent.

Report groups (`report:…`) are excluded from the shared-infrastructure check. A single analyst
report naming the same address as two campaigns is evidence for review, not a reason to split
them.

**Known semantic assumption.** A STIX indicator whose pattern lists a domain and an address
together is read as asserting that they resolve to each other. That is the partner's claim to make,
and the platform records it with the partner's name so it can be weighed against other sources.

## Exports

| Format | Contents | Notes |
|---|---|---|
| CSV, JSON | Every indicator with score, severity, tags, campaigns, sources, times | |
| Blocklist | One value per line, for address, domain and URL indicators | No types or scores, so the consumer decides the threshold |
| STIX 2.1 | A bundle of `indicator` objects with deterministic IDs | **Relationships are not exported** in this release. Patterns use the correct object paths, including `ISSUBSET` for CIDR ranges |
| Excel | An IOCs sheet and a Summary sheet. Summary figures are live `COUNTIF`, `SUM` and `AVERAGE` formulas | The workbook is set to recalculate on open |

## Interfaces

**CLI** (`tip`): `demo`, `feed list|run`, `ingest`, `report`, `search`, `lookup`, `correlate`,
`clusters`, `export`, `serve`.

**HTTP API**: read endpoints are open. Write endpoints (`POST /api/feeds/{name}/run`,
`POST /api/ingest`, `POST /api/reports`) require an `X-API-Key` header that is compared in constant
time. `tip serve` generates a key for the run when `TIP_API_KEY` is unset. The library function
`create_app(settings)` leaves writes open when no key is set, so anything that embeds the app must
set one.

## Security and operating limits

- Write endpoints are authenticated. Read endpoints are not. Put the service behind a reverse proxy
  with TLS and access control before it leaves a trusted network.
- There is no rate limiting, no per-user identity, and no audit log of who ingested what.
- Input is size-limited at the API (10,000,000 characters per ingest, 5,000,000 per report) and feed
  payloads are capped at 50 MB when fetched.
- Parsers are regular expressions and a JSON parser. No input is executed or evaluated.
- Remote feed URLs are fetched with the caller's network access. Restrict egress in production.

## Performance

The derived links are recomputed in full on every ingest. This is simple and always correct, and
it is the first thing that will stop scaling. Measured on the development machine with
`scripts/bench_refresh.py` and synthetic data:

| Indicators | Campaign size | Ingest (s) | Full refresh (s) | Cluster query (s) | Co-occurrence links |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 20 | 0.06 | 0.05 | 0.017 | 9,500 |
| 1,000 | 100 | 0.07 | 0.23 | 0.081 | 49,500 |
| 5,000 | 20 | 0.35 | 0.27 | 0.098 | 47,500 |
| 5,000 | 100 | 0.33 | 1.32 | 0.439 | 247,500 |
| 10,000 | 20 | 0.68 | 0.49 | 0.191 | 95,000 |
| 10,000 | 100 | 0.71 | 2.35 | 0.969 | 495,000 |

Each campaign adds about k²/2 co-occurrence pairs for k members, so the total grows with the number
of indicators times the campaign size: 95,000 links at campaign size 20 against 495,000 at size 100,
for the same 10,000 indicators. That is why the campaign cap exists. At a campaign size of 100, the
refresh cost grows roughly linearly with the number of indicators in the store. Extrapolating from these runs, a full refresh at around 100,000 indicators would take
tens of seconds per ingest. That is the point at which to make the refresh incremental (recompute
only the neighbourhood of changed indicators) and to store co-occurrence as campaign membership
instead of pair rows. These figures are for this synthetic workload, not for production data.

## Extension points

- **A new feed format** is a parser in `feeds/parsers.py` added to `PARSERS`, returning a
  `ParseResult`. Nothing else changes.
- **A new export** is a function in `exporters.py` and an entry in `EXPORT_FORMATS`.
- **A new link origin** is a value of `origin` in the links table and an eligibility rule in
  `Correlator.clusters`. Keep the rule explicit. Do not let a new origin join clusters by default.
