"""Scoring: noisy-OR, exponential decay and severity labels."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tip.scoring import combine, decay, severity

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)


def test_combine_is_noisy_or_and_stays_in_range():
    assert combine([]) == 0.0
    assert combine([0.5, 0.5]) == pytest.approx(0.75)
    assert combine([1.0, 0.2]) == 1.0
    assert combine([2.0]) == 1.0
    assert combine([-1.0]) == 0.0


def test_decay_halves_once_per_half_life():
    assert decay(0.8, NOW - timedelta(days=30), NOW, 30.0) == pytest.approx(0.4)
    assert decay(0.8, NOW - timedelta(days=60), NOW, 30.0) == pytest.approx(0.2)


def test_future_sightings_do_not_gain_score():
    assert decay(0.8, NOW + timedelta(days=5), NOW, 30.0) == pytest.approx(0.8)


def test_zero_half_life_disables_decay():
    assert decay(0.8, NOW - timedelta(days=900), NOW, 0) == pytest.approx(0.8)


@pytest.mark.parametrize("tags, score, expected", [
    (("c2",), 0.85, "critical"),
    (("c2",), 0.5, "high"),
    ((), 0.75, "high"),
    (("phishing",), 0.5, "medium"),
    ((), 0.45, "medium"),
    ((), 0.1, "low"),
])
def test_severity_labels(tags, score, expected):
    assert severity(tags, score) == expected
