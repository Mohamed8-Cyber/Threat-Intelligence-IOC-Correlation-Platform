"""Parsers that turn raw feed payloads (CSV, plain text, STIX 2.1 JSON) into observations.

Each parser returns a ParseResult. Malformed rows are counted in `rejected` rather than
aborting the whole feed, because real feeds always contain some bad lines.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable

from ..models import IOCType, Observation, ParseResult, campaign_key, from_iso
from ..normalize import parse_ioc

_TYPE_ALIASES = {
    "ip": IOCType.IPV4,
    "ipv4": IOCType.IPV4,
    "ipv6": IOCType.IPV6,
    "cidr": IOCType.CIDR,
    "domain": IOCType.DOMAIN,
    "fqdn": IOCType.DOMAIN,
    "url": IOCType.URL,
    "email": IOCType.EMAIL,
    "md5": IOCType.MD5,
    "sha1": IOCType.SHA1,
    "sha-1": IOCType.SHA1,
    "sha256": IOCType.SHA256,
    "sha-256": IOCType.SHA256,
}

# One comparison inside a STIX pattern, e.g. domain-name:value = 'x' or ipv4-addr:value ISSUBSET 'y'.
# Brackets are optional, so a pattern with several comparisons is read as a whole.
_STIX_COMPARISON = re.compile(
    r"(?P<obj>ipv4-addr|ipv6-addr|domain-name|url|email-addr|file)\s*:\s*"
    r"(?P<prop>value|hashes\.'?(?P<algo>[A-Za-z0-9-]+)'?)\s*"
    r"(?P<op>=|ISSUBSET)\s*'(?P<val>[^']+)'"
)
_STIX_OBJECTS = {
    "ipv4-addr": IOCType.IPV4,
    "ipv6-addr": IOCType.IPV6,
    "domain-name": IOCType.DOMAIN,
    "url": IOCType.URL,
    "email-addr": IOCType.EMAIL,
}
_STIX_HASHES = {"MD5": IOCType.MD5, "SHA-1": IOCType.SHA1, "SHA-256": IOCType.SHA256}


def _tags(items: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({str(t).strip().lower() for t in items if str(t).strip()}))


def _confidence(raw: str | None, default: float) -> float:
    """Accept 0-1 or 0-100. Values above 1 are read as percentages."""
    if raw is None or str(raw).strip() == "":
        return default
    value = float(raw)
    if value > 1.0:
        value /= 100.0
    return min(max(value, 0.0), 1.0)


def parse_csv(text: str, source: str, default_confidence: float = 0.5) -> ParseResult:
    """Columns: type, value, confidence, tags, campaign, related, seen_at (only value is required)."""
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    observations: list[Observation] = []
    rejected = 0
    for row in csv.DictReader(lines):
        fields = {str(k or "").strip().lower(): str(v or "").strip() for k, v in row.items()}
        try:
            kind, value = parse_ioc(fields.get("value", ""),
                                    _TYPE_ALIASES.get(fields.get("type", "").lower()))
            observations.append(Observation(
                ioc_type=kind,
                value=value,
                source=source,
                confidence=_confidence(fields.get("confidence"), default_confidence),
                tags=_tags(re.split(r"[;|]", fields.get("tags", ""))),
                campaign=campaign_key(fields.get("campaign")),
                seen_at=from_iso(fields["seen_at"]) if fields.get("seen_at") else None,
                related=(parse_ioc(fields["related"]),) if fields.get("related") else (),
            ))
        except (ValueError, TypeError):
            rejected += 1
    return ParseResult(observations, rejected)


def parse_text(text: str, source: str, default_confidence: float = 0.5) -> ParseResult:
    """One indicator per line. The first token is used, so trailing comments are ignored."""
    observations: list[Observation] = []
    rejected = 0
    for line in text.splitlines():
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        token = re.split(r"[\s,;]+", token)[0]
        try:
            kind, value = parse_ioc(token)
        except ValueError:
            rejected += 1
            continue
        observations.append(Observation(kind, value, source, confidence=default_confidence))
    return ParseResult(observations, rejected)


def _stix_observables(pattern: str) -> list[tuple[IOCType, str]]:
    found: list[tuple[IOCType, str]] = []
    for match in _STIX_COMPARISON.finditer(pattern):
        obj, algo, val = match.group("obj"), match.group("algo"), match.group("val")
        kind: IOCType | None
        if obj == "file":
            kind = _STIX_HASHES.get((algo or "").upper())
        elif algo is None:
            kind = _STIX_OBJECTS[obj]
            if match.group("op") == "ISSUBSET" and kind in (IOCType.IPV4, IOCType.IPV6):
                kind = IOCType.CIDR
        else:
            kind = None
        if kind is not None:
            found.append((kind, val))
    return found


def parse_stix(text: str, source: str, default_confidence: float = 0.5) -> ParseResult:
    """STIX 2.1 bundle. Indicators become observations. Reports group them into campaigns.

    Observation time is set at ingestion, not from valid_from, so that a bundle published months
    ago is scored as a fresh sighting. Labels become tags.
    """
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid STIX JSON: {exc}") from exc
    objects = bundle.get("objects", []) if isinstance(bundle, dict) else []

    campaign_of: dict[str, str] = {}
    for obj in objects:
        if isinstance(obj, dict) and obj.get("type") == "report" and obj.get("name"):
            key = campaign_key(obj["name"])
            for ref in obj.get("object_refs", []):
                campaign_of.setdefault(ref, key)

    observations: list[Observation] = []
    rejected = 0
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        observables: list[tuple[IOCType, str]] = []
        for kind, raw in _stix_observables(str(obj.get("pattern", ""))):
            try:
                observables.append(parse_ioc(raw, kind))
            except ValueError:
                rejected += 1
        if not observables:
            rejected += 1
            continue
        try:
            confidence = (default_confidence if obj.get("confidence") is None
                          else min(max(float(obj["confidence"]) / 100.0, 0.0), 1.0))
        except (TypeError, ValueError):
            confidence = default_confidence
        tags = _tags(obj.get("labels", []))
        campaign = campaign_of.get(str(obj.get("id", "")))
        for index, (kind, value) in enumerate(observables):
            others = tuple(item for j, item in enumerate(observables) if j != index)
            observations.append(Observation(kind, value, source, confidence, tags, campaign,
                                            None, others))
    return ParseResult(observations, rejected)


PARSERS = {"text": parse_text, "csv": parse_csv, "stix": parse_stix}


def parse(format_name: str, text: str, source: str, default_confidence: float = 0.5) -> ParseResult:
    parser = PARSERS.get(format_name)
    if parser is None:
        raise ValueError(f"unknown feed format {format_name!r}")
    return parser(text, source, default_confidence)
