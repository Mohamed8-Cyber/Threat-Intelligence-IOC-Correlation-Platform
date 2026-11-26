# Council transcript: LLM Council

Council: Default (5 advisors, 5 peer reviewers, 1 chairman)
Session convened: 2026-11-20 08:38 UTC

## Original question

The user's message was "اسال المجلس" ("ask the council"). It named no question, so the question below was framed from the project under construction at the time.

## Framed question

Decision: Before presenting a Python package named "Threat intelligence aggregation and IOC correlation Platform" as a finished project, is its architecture sound for an analyst-facing MVP, and which risks must be fixed or cut first?

Context: The project is being built now and has not yet been executed or tested.

Design:
- Python 3.10+ package `tip`.
- SQLite store with indicators, per-source sightings, links and feed run history.
- Ingestion of CSV, plain-text and STIX 2.1 feeds, and of free-text analyst reports through IOC extraction with refang and defang.
- Per-source reliability, noisy-OR confidence, and exponential decay with a 30-day half-life.
- Domain-level allowlist suppression.
- Correlation through derived links (URL host, parent domain, email domain, CIDR membership), feed-provided links (resolves_to, downloaded_from), co-reporting links from a shared campaign or report, and union-find clusters at weight 0.5 or higher.
- Exports to CSV, JSON, blocklist, STIX 2.1 and xlsx with formulas.
- FastAPI HTTP API, a small dashboard, and a CLI.

Known risks named by the author: pairwise co-reporting links, a full recompute of derived links on every ingest, and noisy-OR double counting when one feed repeats a source.

Stakes: The project will be presented as complete. Analysts may act on scores and clusters, so a false link or an inflated score could lead them to block legitimate infrastructure.

## Advisor responses

### The Contrarian

The architecture has failures that a presentation would expose.

First, related indicators receive full sighting credit. When a passive DNS row says domain X resolves to IP Y, both get a sighting at the row's confidence. A shared CDN or shared-hosting address then looks as malicious as the domain and inherits a score it never earned. Every pivot through that address becomes a false link.

Second, clustering is transitive. Union-find over any link at weight 0.5 or higher merges components. One shared IP, or one report that names a CDN address beside a malicious domain, collapses two unrelated campaigns into one cluster. Co-report links carry exactly 0.5, so they clear the threshold by default.

Third, the cap is silent. A campaign with more than 100 members gets no co-report links and increments a counter that nothing displays. A 400-indicator partner bundle produces zero co-reporting, and nobody is told.

Fourth, the API has no authentication. POST /api/feeds/{name}/run and POST /api/ingest are open, so anyone who can reach the port can change the scores an analyst may act on.

Noisy-OR also assumes independent sources. Two partner feeds that republish the same upstream data double count. In threat intelligence that is the usual case, not the exception.

Do not present this as a finished platform until these have tests that fail on the current code.

### The First Principles Thinker

Start from the analyst's real question. It is not "what does the graph look like?" It is "if I block or hunt this indicator, what else should I block, and how sure am I?" The current design answers the second with one number and the first with one graph.

The root problem is that the design stores three different claims as one kind of edge with one weight. A DNS resolution is an observed fact. A feed saying two indicators appeared together is that source's assertion. Two indicators in the same report are a hint that the author cared about both. All three become a row in the links table with a weight, and clustering treats them equally above 0.5. Equal weights for unequal evidence is the central mistake.

Rebuild around the kind of evidence. Structural links, such as URL host, subdomain and CIDR membership, are computed facts and may form clusters. Feed links, such as resolves_to and downloaded_from, are source assertions with provenance. They may form clusters only when a second source corroborates them. Co-reporting is a suggestion for an analyst to read. It should never merge clusters.

The score question follows from this. A 90 percent score means nothing unless it is defined. Decide whether it is a triage rank, a probability or a severity, and write that definition into the product.

Before presenting, answer one question: are we building a graph database or a triage tool? The deck describes the first, while the value lies in the second.

### The Executor

Here is what happens on Monday morning. Nothing in this project has been executed. The package, the tests and the demo run do not yet exist as working code, so every claim in the deck is still a claim. That outranks every design issue above.

The practical order:

1. Build the package and run the test suite. Include one test where a shared IP must not merge two campaigns, and one where a repeated source must not raise the score. If either fails, fix the code before anything else.
2. Run the demo once on a fresh database and copy the real numbers into the deck. Show measured counts, not planned ones.
3. Cut the STIX relationship export. It is the part most likely to produce a file that a real STIX consumer rejects, and nobody will check it before the presentation. Keep the indicator export, which is simpler to verify.
4. Keep the xlsx export, because its formulas recalculate and can be checked.
5. Keep the dashboard small: one table and one graph.

Refreshing all derived links on each ingest is acceptable for an MVP of a few thousand indicators. State that limit in the README and measure it once. Do not optimize before measuring.

If the tests reveal the related-indicator confidence problem, the fix is small. Give related indicators a reduced sighting, or none.

### The Outsider

I have no background here, so I will say what confuses me.

The project uses "IOC", then "indicator", then "observation", then "sighting". Are these the same thing? A reader outside the field will not know. Define each once and use one word.

The score is called confidence in the code and score on the dashboard, and the dashboard shows it as a percentage. A percentage invites reading it as the chance that something is malicious. The documentation says it is a combined, decayed value. Those are different claims, and a newcomer will take the percentage at face value.

Noisy-OR is a term most people outside statistics have never heard. The slide needs a plain sentence: several independent sources agreeing raises the score, but one source repeating itself does not.

Suppression is silent on the dashboard. login.microsoft.com simply disappears, and the only trace is a count in a report that a user will not open. An analyst who searches for that domain and finds nothing will assume it was never seen.

The demo uses fictional .example and .test names. That is correct, but the deck should say so on the slide, or the audience may take the data for real.

I would present decay with one picture: an indicator's score falling over a month. One chart does more than the formula.

### The Expansionist

The upside is larger than the current framing admits, and most of it comes from the change the First Principles voice asks for.

If every link carries provenance (which source, which date, which evidence), the platform stops being a list of indicators and becomes an evidence ledger. That supports three things a presentation can show as real. An analyst can see why two indicators are connected. STIX relationship exports carry actual meaning. A corroborated shared link becomes a candidate for sharing with a sector information-sharing group.

Decay gives a second opening. A 30-day half-life means an indicator's score falls with age, so the platform can generate blocklists with time-to-live values instead of accumulating stale entries. Most firewall blocklists fail because nothing expires. A competitor with a flat list cannot match that.

Pivoting is the third. The data model already supports moving from a hash to a URL, to a host, to an IP. Adding enrichment fields such as ASN or registration date later is cheap.

Do not expand scope before the core works. But add provenance now. The links table has an origin column that says feed or derived, and no source column that says which feed. Adding that later means migrating every stored link.

### Peer review

**Review 1**

1. Strongest: Response D. It names concrete failure mechanisms (shared-address credit, transitive clustering, a silent cap) that can be checked against the code.
2. Biggest blind spot: Response D proposes no repair order and no definition of done. Response B supplies both.
3. Missed by all: nobody proposed measuring cluster precision against a labelled set of known campaigns. Without ground truth, the council can say the correlation is plausible, not that it is correct.

**Review 2**

1. Strongest: Response A. It identifies the central mistake, which is treating three kinds of evidence as one weighted edge type.
2. Biggest blind spot: Response A gives no schema. Its rebuild stays abstract, and an implementer cannot start from it.
3. Missed by all: the time dimension of links. Decay applies to scores, but links carry no timestamp, so a two-year-old co-report can still merge clusters today.

**Review 3**

1. Strongest: Response B. Its order is executable: tests, then demo numbers, then cuts.
2. Biggest blind spot: Response B calls the STIX export a cut without checking what the deck would claim. If the slides say STIX support, the slides must change along with the code.
3. Missed by all: the 30-day half-life and the 0.5 cluster threshold are unvalidated constants. The deck presents them as design choices, but nothing in the project supports their values.

**Review 4**

1. Strongest: Response E. Its point that links lack a source column is concrete and expensive to fix later.
2. Biggest blind spot: Response E assumes provenance-rich links make sector sharing viable. It ignores licence and traffic-light-protocol restrictions on the feeds themselves.
3. Missed by all: conflicting evidence. If one feed marks a domain benign and another marks it malicious, the model has no negative evidence and no rule for resolving the conflict.

**Review 5**

1. Strongest: Response C. It catches how an analyst will misread the score as a probability, which is the most likely failure in a presentation.
2. Biggest blind spot: Response C addresses wording, not correctness. A clear label on a wrong cluster is still wrong.
3. Missed by all: the API is a write surface with no authentication. Response D mentions it briefly, but no one ranked it against the correlation defects.

### Anonymization map

- Response A: The First Principles Thinker
- Response B: The Executor
- Response C: The Outsider
- Response D: The Contrarian
- Response E: The Expansionist

## Chairman's synthesis

### Where the Council Agrees

- The central defect is that different kinds of evidence share one edge type and one threshold. A resolution record, a source assertion and a co-report hint all cluster at weight 0.5 or higher. (First Principles, Contrarian, Outsider, Expansionist, Review 4)
- The project has never run. Nothing in the deck is verified until tests exist and the demo is executed. (Executor, Contrarian)
- The score cannot be shown as a percentage without a written definition. (Outsider, First Principles)

### Where the Council Clashes

- **Co-reporting in clusters.** The Expansionist wants co-report links to enrich the graph. The Contrarian and First Principles want them out of clustering. The verdict sides with exclusion: a shared report should suggest a relationship for review, not merge two campaigns.
- **STIX relationship export.** The Executor would cut it; the Expansionist treats it as evidence. The verdict sides with the Executor for this release, because a STIX file that a consumer rejects is worse than no file. The provenance column stays.
- **Refreshing every link on each ingest.** The Executor accepts it at MVP scale; the Contrarian sees the scale risk. Both are right at different sizes. Accept it, state the limit, and measure before optimizing.

### Blind Spots the Council Caught

- Related indicators receive full sighting credit. An IP that a passive DNS row lists beside a malicious domain becomes malicious-looking in its own right, and shared hosting makes this a systematic error.
- Oversized campaigns are skipped without a visible warning.
- Links have no timestamp, so decay never reaches clustering. Old links keep merging campaigns indefinitely (Review 2).
- Repeated upstream feeds violate the independence that noisy-OR assumes, so the score rises when it should not.
- There is no ground-truth test, so correlation may be plausible without being correct (Review 1).
- Conflicting evidence has no resolution rule (Review 4).
- The write endpoints are unauthenticated.

### The Recommendation

Keep the architecture for an analyst-facing MVP, but do not present it as a finished platform yet. Present it as an MVP with measured limits. Before the deck is written:

1. Clusters use only structural links and feed-asserted links that a second source corroborates. Co-reporting becomes a suggestion shown beside a cluster, never a member of it.
2. Related indicators receive no sighting credit of their own, or a reduced one. The link carries the evidence instead.
3. Links store the source name and a timestamp, and cluster eligibility decays with the link's age.
4. The dashboard and the deck call the score a triage rank, defined in one sentence.
5. Oversized campaigns appear in the report with a count and a warning.
6. Write endpoints require an API key.
7. The deck states that all data is synthetic and uses reserved .example and .test names.
8. The STIX relationship export is removed from this release. The indicator export remains.

### The One Thing to Do First

Write one failing test: a single IP seen in two unrelated campaigns must not merge them into one cluster. Fix the clustering until that test passes, then run the demo.
