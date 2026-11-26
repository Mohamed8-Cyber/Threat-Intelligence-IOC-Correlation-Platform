# Council decisions

Before the platform was built, its design was put to a council of five advisors using the
configurable council method: each advisor argued from one lens, the advisors reviewed each other
anonymously, and a chairman wrote the verdict. The full transcript and the visual report are kept
alongside this file in [council/](council/).

The question put to the council was whether the architecture is sound for an analyst-facing MVP,
what its largest correctness and scale risks are, and what should be cut or fixed before it is
presented as finished.

The advisors were The Contrarian, The First Principles Thinker, The Executor, The Outsider and
The Expansionist. The council's verdict was to keep the architecture for an MVP but **not to present
it as a finished platform** until the items below were applied.

## Where the council agreed

- Different kinds of evidence shared one edge type and one threshold. A resolution record, a source
  assertion and a co-report hint all clustered at weight 0.5 or higher.
- The project had never run, so nothing in it was verified.
- The score could not be shown as a percentage without a written definition.

## Where the council disagreed, and what was decided

| Question | Positions | Decision |
|---|---|---|
| Should co-reported indicators join clusters? | The Expansionist wanted them to enrich the graph. The Contrarian and First Principles wanted them out of clustering | **Out.** A shared report suggests a relation for review. It does not merge two campaigns |
| Should STIX relationships be exported? | The Executor would cut them. The Expansionist treated them as evidence | **Cut for this release.** A STIX file that a consumer rejects is worse than none. Provenance stays in the store |
| Should every link be refreshed on each ingest? | The Executor accepted it at MVP scale. The Contrarian saw the scale risk | **Accepted, limit stated, and measured.** The benchmark is in [ARCHITECTURE.md](ARCHITECTURE.md#performance) |

## Applied recommendations

| # | Council recommendation | Status | Where it is enforced |
|---|---|---|---|
| 1 | Clusters use only structural links and feed links that a second source corroborates. Co-reporting is a suggestion, never a member | Applied | `Correlator.clusters`; tests `test_feed_link_needs_a_second_source_to_cluster`, `test_co_reported_pairs_are_suggestions_and_never_clusters` |
| 2 | Related indicators receive no sighting credit, or a reduced one | Applied, full removal: confidence 0 | `Aggregator._store_observation`; test `test_context_sighting_gives_no_score_and_no_source_credit` |
| 3 | Links store the source name and a timestamp, and cluster eligibility decays with age | Applied | `links` table columns; `Correlator.clusters`; test `test_stale_corroborated_links_stop_clustering` |
| 4 | The score is called a triage rank, defined in one sentence | Applied | Dashboard, CLI, README, ARCHITECTURE |
| 5 | Oversized campaigns are reported, with a count | Applied as a count in every ingest report and the CLI. Not yet a banner on the dashboard | `Correlator.refresh`; test `test_oversized_campaign_is_skipped_and_counted` |
| 6 | Write endpoints require an API key | Applied. When no key is configured, `tip serve` generates one for the run and prints it | `api.require_key`; `cli.main`; test `test_write_endpoints_require_the_api_key` |
| 7 | The deck and dashboard state that data is synthetic and uses reserved names | Applied | Dashboard intro, README, deck |
| 8 | Remove the STIX relationship export; keep indicator export | Applied | `exporters.to_stix` exports indicators only |

## The one thing to do first

The council's first instruction was a test: a single address seen in two unrelated campaigns must
not merge them into one cluster. That test is `test_shared_address_does_not_merge_unrelated_campaigns`.

The exclusion rule was already in the clustering code when the test was added, so the test was a
check on the rule rather than a driver of it. To confirm it actually guards the rule, the
shared-infrastructure exclusion was disabled for one run, and the test failed. The same check on the
two-source corroboration rule also made its test fail. Both rules were then restored and the full
suite passed.

## Open items the council raised that remain

- **Conflicting evidence has no resolution rule.** When one source says an address is benign and
  another says it is malicious, the platform keeps both sightings and scores the malicious one. It
  does not yet record the disagreement as a finding.
- **There is no ground-truth evaluation.** Correlation is correct on the synthetic data, which was
  built to contain the cases the rules describe. Whether it is correct on real feeds is unmeasured.
- **Derived links are recomputed in full** on each ingest. Measured limits are in the architecture
  document.
- **Repeated upstream feeds are not detected.** Two feeds that copy one another are counted as two
  sources, which overstates confidence. Detecting that needs provenance the feeds do not carry.
