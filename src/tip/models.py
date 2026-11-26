"""Core domain types shared by every layer: indicator types, observations and time helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

# Campaign names that start with this prefix come from analyst reports. They group indicators
# for co-reporting suggestions but never count as evidence that infrastructure is shared.
REPORT_PREFIX = "report:"


class IOCType(str, Enum):
    """Kinds of indicator the platform understands."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


HASH_TYPES = frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256})


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(moment: datetime) -> str:
    aware = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).isoformat(timespec="seconds")


def from_iso(text: str) -> datetime:
    parsed = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def campaign_key(raw: str | None) -> str | None:
    """Canonical campaign identifier, so 'ShadowLoader' and 'shadowloader' are the same campaign."""
    if raw is None:
        return None
    key = re.sub(r"\s+", "-", str(raw).strip().lower())
    return key or None


@dataclass(frozen=True)
class Observation:
    """One sighting of an indicator, as reported by a single source."""

    ioc_type: IOCType
    value: str
    source: str
    confidence: float = 0.5
    tags: tuple[str, ...] = ()
    campaign: str | None = None
    seen_at: datetime | None = None
    # Indicators reported alongside this one (for example the IP in the same passive DNS row).
    related: tuple[tuple[IOCType, str], ...] = ()


@dataclass
class ParseResult:
    observations: list[Observation]
    rejected: int = 0
