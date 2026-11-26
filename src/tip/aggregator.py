"""Ingestion pipeline: load a payload, parse it, drop allowlisted hosts, store sightings and record the run.

Indicators reported alongside another (the IP in a passive DNS row, for example) are stored with a
zero-confidence context sighting. They receive no score credit of their own. The link between the
two carries the evidence, so a shared CDN address cannot inherit a malicious domain's score.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import httpx

from .correlation import infer_relation
from .extract import extract_iocs
from .feeds import FeedSpec, parse
from .models import REPORT_PREFIX, Observation, ParseResult, campaign_key, to_iso, utcnow
from .normalize import host_of, in_allowlist
from .storage import Store

MAX_PAYLOAD_BYTES = 50 * 1024 * 1024


@dataclass
class IngestReport:
    source: str
    accepted: int = 0
    new_indicators: int = 0
    rejected: int = 0
    suppressed: int = 0
    links_added: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def load_payload(spec: FeedSpec, timeout: float) -> str:
    """Read a feed from its local path or fetch it from its URL."""
    if spec.path is not None:
        return Path(spec.path).read_text(encoding="utf-8", errors="replace")
    response = httpx.get(spec.url, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    if len(response.content) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"feed {spec.name!r} exceeds {MAX_PAYLOAD_BYTES} bytes")
    return response.text


class Aggregator:
    def __init__(self, store: Store, allowlist: tuple[str, ...] = (),
                 clock: Callable[[], datetime] = utcnow) -> None:
        self.store = store
        self.allowlist = tuple(allowlist)
        self._clock = clock

    def ingest(self, result: ParseResult, *, source: str, reliability: float) -> IngestReport:
        report = IngestReport(source=source, rejected=result.rejected)
        try:
            for observation in result.observations:
                self._store_observation(observation, source, reliability, report)
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        return report

    def ingest_feed(self, spec: FeedSpec, timeout: float) -> IngestReport:
        run_at = to_iso(self._clock())
        try:
            payload = load_payload(spec, timeout)
            report = self.ingest(parse(spec.format, payload, spec.name),
                                 source=spec.name, reliability=spec.reliability)
        except Exception as exc:
            self.store.record_feed_run(feed=spec.name, fmt=spec.format,
                                       reliability=spec.reliability, last_run=run_at,
                                       status=f"error: {exc}", report={})
            raise
        self.store.record_feed_run(feed=spec.name, fmt=spec.format,
                                   reliability=spec.reliability, last_run=run_at,
                                   status="ok", report=report.as_dict())
        return report

    def ingest_report(self, text: str, *, source: str, title: str | None = None,
                      reliability: float = 0.7) -> IngestReport:
        """Extract indicators from analyst prose. They are grouped as one report for co-reporting."""
        key = campaign_key(title) or hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]
        campaign = f"{REPORT_PREFIX}{key}"
        observations = [
            Observation(kind, value, source, confidence=0.6, campaign=campaign)
            for kind, value in extract_iocs(text)
        ]
        return self.ingest(ParseResult(observations), source=source, reliability=reliability)

    # -- internals -------------------------------------------------------
    def _store_observation(self, obs: Observation, source: str, reliability: float,
                           report: IngestReport) -> None:
        if self._suppressed(obs.ioc_type, obs.value):
            report.suppressed += 1
            return
        seen_at = obs.seen_at or self._clock()
        ioc_id, created = self.store.record_sighting(
            ioc_type=obs.ioc_type.value, value=obs.value, source=source,
            confidence=obs.confidence, reliability=reliability, tags=obs.tags,
            campaign=obs.campaign or "", seen_at=seen_at,
        )
        report.accepted += 1
        report.new_indicators += int(created)

        for rel_type, rel_value in obs.related:
            if self._suppressed(rel_type, rel_value):
                report.suppressed += 1
                continue
            rel_id, rel_created = self.store.record_sighting(
                ioc_type=rel_type.value, value=rel_value, source=source,
                confidence=0.0, reliability=reliability, tags=(), campaign="", seen_at=seen_at,
            )
            report.new_indicators += int(rel_created)
            self.store.add_link(
                src_id=ioc_id, dst_id=rel_id,
                relation=infer_relation(obs.ioc_type, rel_type),
                origin="feed", source=source, weight=obs.confidence, seen_at=seen_at,
            )
            report.links_added += 1

    def _suppressed(self, kind, value: str) -> bool:
        host = host_of(kind, value)
        return host is not None and in_allowlist(host, self.allowlist)
