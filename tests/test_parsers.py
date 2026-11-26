"""Feed parsers: CSV with related columns, plain text and STIX 2.1 bundles."""

from __future__ import annotations

import pytest

from tip.feeds import parse
from tip.feeds.parsers import parse_csv, parse_stix, parse_text
from tip.models import IOCType, campaign_key

from .conftest import SAMPLES


def test_csv_reads_related_column_and_counts_rejections():
    text = ("type,value,confidence,tags,campaign,related\n"
            "domain,evil.example,85,c2;malware,ShadowLoader,198.51.100.23\n"
            "ip,999.1.1.1,50,c2,,\n")
    result = parse_csv(text, "pdns")
    assert result.rejected == 1
    obs = result.observations[0]
    assert obs.ioc_type is IOCType.DOMAIN
    assert obs.confidence == pytest.approx(0.85)
    assert obs.campaign == "shadowloader"
    assert "c2" in obs.tags
    assert obs.related[0] == (IOCType.IPV4, "198.51.100.23")


def test_plain_text_ignores_comment_lines():
    text = "# a comment that mentions 10.0.0.1\n198.51.100.23\nevil.example\n"
    values = {obs.value for obs in parse_text(text, "list").observations}
    assert {"198.51.100.23", "evil.example"} <= values
    assert "10.0.0.1" not in values


def test_stix_bundle_maps_patterns_to_observables():
    bundle = (SAMPLES / "partner_bundle.json").read_text(encoding="utf-8")
    result = parse_stix(bundle, "partner")
    kinds = {obs.ioc_type for obs in result.observations}
    assert {IOCType.IPV4, IOCType.SHA256, IOCType.CIDR} <= kinds


def test_stix_bundle_rejects_unsupported_observables():
    bundle = (SAMPLES / "partner_bundle.json").read_text(encoding="utf-8")
    assert parse_stix(bundle, "partner").rejected >= 1


def test_stix_report_objects_become_campaigns():
    bundle = (SAMPLES / "partner_bundle.json").read_text(encoding="utf-8")
    campaigns = {obs.campaign for obs in parse_stix(bundle, "partner").observations if obs.campaign}
    assert "shadowloader" in campaigns


def test_campaign_keys_are_normalized():
    assert campaign_key("ShadowLoader") == "shadowloader"
    assert campaign_key("  PhishKit   Ledger ") == "phishkit-ledger"


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError):
        parse("xml", "<x/>", "s")
