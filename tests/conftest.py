"""Shared fixtures. Every test builds its own SQLite database under pytest's tmp_path."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from tip.aggregator import Aggregator
from tip.correlation import Correlator
from tip.feeds import parse
from tip.storage import Store

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "data" / "samples"
NOW = datetime(2026, 11, 20, 9, 0, tzinfo=timezone.utc)
ALLOWLIST = ("microsoft.com", "example.com")


@pytest.fixture
def samples() -> Path:
    return SAMPLES


@pytest.fixture
def store(tmp_path):
    db = Store(tmp_path / "tip.db")
    yield db
    db.close()


@pytest.fixture
def aggregator(store):
    return Aggregator(store, allowlist=ALLOWLIST, clock=lambda: NOW)


@pytest.fixture
def correlator(store):
    return Correlator(store, half_life_days=30.0, max_campaign_members=100,
                      max_fan_in=10, min_sources=2)


@pytest.fixture
def feed(aggregator, correlator):
    """Ingest text in one format from one named source, then refresh the derived links."""

    def ingest(fmt: str, text: str, source: str, reliability: float = 0.8):
        report = aggregator.ingest(parse(fmt, text, source), source=source,
                                   reliability=reliability)
        correlator.refresh()
        return report

    return ingest
