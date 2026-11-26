"""Application service: the one object the CLI and HTTP API talk to.

It wires storage, ingestion, correlation and export together, and presents results with the
triage score and severity applied. All public methods take the lock, so one SQLite connection is
safe to share across the API's worker threads.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .aggregator import Aggregator, IngestReport
from .config import Settings
from .correlation import RELATION_LABELS, Correlator
from .exporters import to_blocklist, to_csv, to_json, to_stix, to_xlsx
from .feeds import FeedSpec, load_feeds, parse
from .models import REPORT_PREFIX, IOCType, from_iso, utcnow
from .normalize import parse_ioc
from .scoring import decay, severity
from .storage import Store

EXPORT_FORMATS = ("csv", "json", "stix", "blocklist", "xlsx")


class TIPService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store = Store(settings.db_path)
        self.aggregator = Aggregator(self.store, settings.allowlist)
        self.correlator = Correlator(
            self.store,
            half_life_days=settings.half_life_days,
            max_campaign_members=settings.max_campaign_members,
            max_fan_in=settings.max_fan_in,
            min_sources=settings.min_sources,
        )
        self._lock = threading.RLock()
        feeds_path = Path(settings.feeds_file)
        self._feeds: dict[str, FeedSpec] = {}
        if feeds_path.exists():
            self._feeds = {spec.name: spec for spec in load_feeds(feeds_path)}

    def close(self) -> None:
        self.store.close()

    # -- presentation ----------------------------------------------------
    def _effective(self, row: dict[str, Any]) -> float:
        return decay(row["score"], from_iso(row["last_seen"]), utcnow(),
                     self.settings.half_life_days)

    def _present(self, row: dict[str, Any]) -> dict[str, Any]:
        score = self._effective(row)
        return {
            "id": row["id"],
            "type": row["ioc_type"],
            "value": row["value"],
            "score": score,
            "severity": severity(row["tags"], score),
            "tags": row["tags"],
            "campaigns": row["campaigns"],
            "sources": row["sources"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }

    def _finish(self, report: IngestReport) -> dict[str, Any]:
        out = report.as_dict()
        out["derived_links"] = self.correlator.refresh()
        return out

    # -- feeds and ingestion ---------------------------------------------
    def feed_specs(self) -> list[FeedSpec]:
        return list(self._feeds.values())

    def feeds(self) -> list[dict[str, Any]]:
        runs = {run["feed"]: run for run in self.store.feed_runs()}
        out = []
        for spec in self._feeds.values():
            run = runs.get(spec.name, {})
            out.append({
                "name": spec.name,
                "format": spec.format,
                "reliability": spec.reliability,
                "origin": spec.path or spec.url,
                "last_run": run.get("last_run"),
                "status": run.get("status", "never run"),
                "accepted": run.get("accepted", 0),
                "rejected": run.get("rejected", 0),
                "suppressed": run.get("suppressed", 0),
            })
        return out

    def run_feed(self, name: str) -> dict[str, Any]:
        with self._lock:
            if name not in self._feeds:
                raise KeyError(name)
            report = self.aggregator.ingest_feed(self._feeds[name], self.settings.fetch_timeout)
            return self._finish(report)

    def ingest_payload(self, *, text: str, source: str, format_name: str,
                       reliability: float) -> dict[str, Any]:
        with self._lock:
            result = parse(format_name, text, source)
            return self._finish(self.aggregator.ingest(result, source=source,
                                                       reliability=reliability))

    def ingest_report(self, *, text: str, source: str, title: str | None,
                      reliability: float) -> dict[str, Any]:
        with self._lock:
            return self._finish(self.aggregator.ingest_report(
                text, source=source, title=title, reliability=reliability))

    # -- queries ---------------------------------------------------------
    def search(self, *, text: str | None = None, ioc_type: str | None = None,
               min_score: float = 0.0, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.store.search(text=text, ioc_type=ioc_type, min_score=min_score)
            items = [self._present(row) for row in rows]
        items = [item for item in items if item["score"] >= min_score]
        items.sort(key=lambda item: (item["score"], item["last_seen"]), reverse=True)
        return items[:limit]

    def lookup(self, ioc_type: str, value: str) -> dict[str, Any] | None:
        kind, normalized = parse_ioc(value, IOCType(ioc_type))
        with self._lock:
            row = self.store.find_ioc(kind.value, normalized)
            return self._present(row) if row else None

    def investigate(self, ioc_type: str, value: str, depth: int = 2) -> dict[str, Any] | None:
        kind, normalized = parse_ioc(value, IOCType(ioc_type))
        with self._lock:
            row = self.store.find_ioc(kind.value, normalized)
            if row is None:
                return None
            hood = self.correlator.neighborhood(row["id"], depth)
            nodes = []
            for node_id, hop in hood["hops"].items():
                node = self.store.get_ioc(node_id)
                if node is not None:
                    nodes.append({**self._present(node), "hop": hop})
            edges = [{**edge, "label": RELATION_LABELS.get(edge["relation"], edge["relation"])}
                     for edge in hood["edges"]]
            root = self._present(row)
        nodes.sort(key=lambda n: (n["hop"], -n["score"]))
        return {"root": root, "depth": depth, "nodes": nodes, "edges": edges}

    def clusters(self, min_weight: float | None = None, limit: int = 20) -> dict[str, Any]:
        threshold = self.settings.cluster_min_weight if min_weight is None else min_weight
        with self._lock:
            raw = self.correlator.clusters(min_weight=threshold, limit=limit)
            clusters = []
            for cluster in raw["clusters"]:
                members = [self._present(self.store.get_ioc(i)) for i in cluster["member_ids"]]
                members.sort(key=lambda m: m["score"], reverse=True)
                names = {c for m in members for c in m["campaigns"]}
                clusters.append({
                    "size": len(members),
                    "max_score": members[0]["score"] if members else 0.0,
                    "campaigns": sorted(c for c in names if not c.startswith(REPORT_PREFIX)),
                    "reports": sorted(c[len(REPORT_PREFIX):] for c in names
                                      if c.startswith(REPORT_PREFIX)),
                    "tags": sorted({t for m in members for t in m["tags"]}),
                    "relations": cluster["relations"],
                    "members": members[:25],
                })
            shared = []
            for item in raw["shared_infrastructure"]:
                node = self._present(self.store.get_ioc(item["id"]))
                shared.append({
                    "id": node["id"], "type": node["type"], "value": node["value"],
                    "score": node["score"], "reasons": item["reasons"],
                    "neighbours": item["neighbours"],
                })
        return {"clusters": clusters, "shared_infrastructure": shared}

    def stats(self) -> dict[str, Any]:
        with self._lock:
            base = self.store.stats()
        base["clusters"] = len(self.clusters(limit=10_000)["clusters"])
        base["shared_infrastructure"] = len(self.clusters(limit=10_000)["shared_infrastructure"])
        base["feeds"] = len(self._feeds)
        return base

    # -- export ----------------------------------------------------------
    def export(self, fmt: str, *, ioc_type: str | None = None, min_score: float = 0.0,
               path: str | Path | None = None) -> str | Path:
        if fmt not in EXPORT_FORMATS:
            raise ValueError(f"unknown export format {fmt!r}")
        rows = self.search(ioc_type=ioc_type, min_score=min_score, limit=1_000_000)
        if fmt == "csv":
            return to_csv(rows)
        if fmt == "json":
            return to_json(rows)
        if fmt == "blocklist":
            return to_blocklist(rows)
        if fmt == "stix":
            return json.dumps(to_stix(rows), indent=2)
        if path is None:
            raise ValueError("the xlsx export needs a target path")
        return to_xlsx(rows, path)
