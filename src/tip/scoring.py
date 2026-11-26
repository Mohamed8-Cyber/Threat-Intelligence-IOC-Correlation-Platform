"""Scoring: noisy-OR across independent sources, exponential decay and triage severity.

The score is a triage rank, not a probability. Each source contributes once, at its best
confidence, weighted by how reliable that source is. Several independent sources raise the score.
A source that repeats itself does not. Scores fall with age; the half-life is a setting.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

HIGH_TAGS = frozenset({"ransomware", "c2", "botnet", "apt", "stealer", "exploit", "malware", "backdoor"})
MEDIUM_TAGS = frozenset({"phishing", "miner", "scanner", "spam", "suspicious", "hosting-range"})


def combine(contributions: Iterable[float]) -> float:
    """Noisy-OR: one minus the product of (1 - contribution). Never exceeds 1.0."""
    remaining = 1.0
    for contribution in contributions:
        remaining *= 1.0 - min(max(contribution, 0.0), 1.0)
    return round(1.0 - remaining, 4)


def decay(value: float, seen: datetime, now: datetime, half_life_days: float) -> float:
    """Halve `value` every `half_life_days` since `seen`."""
    if half_life_days <= 0:
        return round(value, 4)
    age_days = max((now - seen).total_seconds(), 0.0) / 86400.0
    return round(value * 0.5 ** (age_days / half_life_days), 4)


def severity(tags, score: float) -> str:
    """Map tags and triage score to a severity label for analysts."""
    tagset = set(tags)
    if score >= 0.8 and tagset & HIGH_TAGS:
        return "critical"
    if tagset & HIGH_TAGS or score >= 0.7:
        return "high"
    if tagset & MEDIUM_TAGS or score >= 0.4:
        return "medium"
    return "low"
