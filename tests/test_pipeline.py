"""Pipeline rules: corroboration, shared infrastructure, scoring credit, idempotence, decay."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tip.aggregator import Aggregator
from tip.cli import main as cli_main
from tip.correlation import Correlator
from tip.feeds import parse

from .conftest import ALLOWLIST, SAMPLES

HEADER = "type,value,confidence,tags,campaign,related\n"

# One address seen in two unrelated campaigns. Both domains resolve to it.
ALPHA_BETA = HEADER + (
    "domain,alpha-c2.example,90,c2,Alpha,198.51.100.23\n"
    "domain,beta-c2.example,90,c2,Beta,198.51.100.23\n"
    "ip,198.51.100.23,60,scanner,Alpha,\n"
    "ip,198.51.100.23,60,scanner,Beta,\n"
)

SOLO = HEADER + "domain,solo-c2.example,90,c2,Solo,203.0.113.9\n"


def test_shared_address_does_not_merge_unrelated_campaigns(feed, correlator, store):
    """The council's first test: a shared address must not join two unrelated campaigns."""
    feed("csv", ALPHA_BETA, "feed-one")
    feed("csv", ALPHA_BETA, "feed-two", reliability=0.9)

    result = correlator.clusters(min_weight=0.3)
    alpha = store.find_ioc("domain", "alpha-c2.example")["id"]
    beta = store.find_ioc("domain", "beta-c2.example")["id"]
    ip = store.find_ioc("ipv4", "198.51.100.23")["id"]

    for cluster in result["clusters"]:
        assert not {alpha, beta} <= set(cluster["member_ids"])

    shared = {item["id"]: item for item in result["shared_infrastructure"]}
    assert ip in shared
    assert any(reason.startswith("seen in 2 campaigns") for reason in shared[ip]["reasons"])


def test_feed_link_needs_a_second_source_to_cluster(feed, correlator, store):
    feed("csv", SOLO, "feed-one")
    assert correlator.clusters(min_weight=0.3)["clusters"] == []

    feed("csv", SOLO, "feed-two")
    clusters = correlator.clusters(min_weight=0.3)["clusters"]
    solo = store.find_ioc("domain", "solo-c2.example")["id"]
    ip = store.find_ioc("ipv4", "203.0.113.9")["id"]
    assert len(clusters) == 1
    assert {solo, ip} <= set(clusters[0]["member_ids"])


def test_co_reported_pairs_are_suggestions_and_never_clusters(feed, correlator):
    text = HEADER + (
        "domain,gamma-one.example,80,phishing,Gamma,\n"
        "domain,gamma-two.example,80,phishing,Gamma,\n"
    )
    counts = feed("csv", text, "feed-one")
    assert counts.accepted == 2
    stored = correlator.clusters(min_weight=0.0)
    assert stored["clusters"] == []


def test_context_sighting_gives_no_score_and_no_source_credit(feed, store):
    feed("csv", HEADER + "domain,cdn-host.example,85,c2,Loader,198.51.100.23\n", "pdns")

    address = store.find_ioc("ipv4", "198.51.100.23")
    domain = store.find_ioc("domain", "cdn-host.example")
    assert address["score"] == 0.0
    assert address["sources"] == 0
    assert domain["score"] > 0.0
    assert domain["sources"] == 1


def test_one_source_repeating_itself_is_not_double_counted(feed, store):
    text = HEADER + (
        "domain,dup-host.example,50,c2,One,\n"
        "domain,dup-host.example,90,c2,Two,\n"
    )
    feed("csv", text, "dup-feed", reliability=0.8)
    # One contribution per source at its best confidence: 0.9 * 0.8 = 0.72, not a noisy-OR of both.
    assert store.find_ioc("domain", "dup-host.example")["score"] == pytest.approx(0.72, abs=1e-3)


def test_independent_sources_combine_by_noisy_or(feed, store):
    text = HEADER + "domain,two-src.example,50,c2,,\n"
    feed("csv", text, "src-a", reliability=1.0)
    feed("csv", text, "src-b", reliability=1.0)
    assert store.find_ioc("domain", "two-src.example")["score"] == pytest.approx(0.75, abs=1e-3)


def test_reingesting_the_same_feed_changes_nothing(feed, store):
    feed("csv", ALPHA_BETA, "feed-one")
    before = store.stats()
    score = store.find_ioc("domain", "alpha-c2.example")["score"]

    feed("csv", ALPHA_BETA, "feed-one")
    after = store.stats()

    assert after["indicators"] == before["indicators"]
    assert after["sightings"] == before["sightings"]
    assert store.find_ioc("domain", "alpha-c2.example")["score"] == score


def test_allowlisted_hosts_are_suppressed(feed, store):
    report = feed("csv", HEADER + "domain,login.microsoft.com,40,phishing,,\n", "feed-x")
    assert report.suppressed == 1
    assert store.find_ioc("domain", "login.microsoft.com") is None


def test_stale_corroborated_links_stop_clustering(store, correlator):
    """Decay reaches clustering: two-source links from years ago no longer merge anything."""
    old = Aggregator(store, allowlist=ALLOWLIST,
                     clock=lambda: datetime(2025, 1, 1, tzinfo=timezone.utc))
    old.ingest(parse("csv", SOLO, "feed-one"), source="feed-one", reliability=0.9)
    old.ingest(parse("csv", SOLO, "feed-two"), source="feed-two", reliability=0.9)
    correlator.refresh()

    assert correlator.clusters(min_weight=0.3)["clusters"] == []
    # The link still exists; it has simply decayed below the cluster threshold.
    assert len(correlator.clusters(min_weight=0.0)["clusters"]) == 1


def test_oversized_campaign_is_skipped_and_counted(store):
    aggregator = Aggregator(store, allowlist=ALLOWLIST, clock=lambda: datetime(2026, 11, 20, tzinfo=timezone.utc))
    correlator = Correlator(store, max_campaign_members=2)
    text = HEADER + "".join(f"domain,big-{i}.example,50,phishing,Huge,\n" for i in range(3))
    aggregator.ingest(parse("csv", text, "f"), source="f", reliability=0.5)

    counts = correlator.refresh()
    assert counts["oversized_campaigns_skipped"] == 1
    assert counts.get("co_reported", 0) == 0


def test_demo_command_reports_clusters_and_shared_infrastructure(tmp_path, capsys):
    code = cli_main(["--db", str(tmp_path / "demo.db"),
                     "--feeds", str(SAMPLES / "feeds.json"), "demo"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Cluster 1" in out
    assert "Shared infrastructure" in out
    assert "198.51.100.23" in out
