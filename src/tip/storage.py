"""SQLite persistence: indicators, per-source sightings, links and feed run history."""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

from .models import REPORT_PREFIX, to_iso
from .scoring import combine

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type   TEXT NOT NULL,
    value      TEXT NOT NULL,
    score      REAL NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    sources    INTEGER NOT NULL DEFAULT 0,
    tags       TEXT NOT NULL DEFAULT '[]',
    campaigns  TEXT NOT NULL DEFAULT '[]',
    UNIQUE (ioc_type, value)
);
CREATE TABLE IF NOT EXISTS sightings (
    ioc_id     INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    source     TEXT NOT NULL,
    campaign   TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL,
    reliability REAL NOT NULL,
    seen_at    TEXT NOT NULL,
    PRIMARY KEY (ioc_id, source, campaign)
);
CREATE TABLE IF NOT EXISTS links (
    src_id   INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    dst_id   INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    origin   TEXT NOT NULL CHECK (origin IN ('structural', 'feed', 'cooccurrence')),
    source   TEXT NOT NULL,
    weight   REAL NOT NULL DEFAULT 1.0,
    seen_at  TEXT,
    PRIMARY KEY (src_id, dst_id, relation, origin, source)
);
CREATE TABLE IF NOT EXISTS feed_runs (
    feed           TEXT PRIMARY KEY,
    format         TEXT NOT NULL,
    reliability    REAL NOT NULL,
    last_run       TEXT NOT NULL,
    status         TEXT NOT NULL,
    accepted       INTEGER NOT NULL DEFAULT 0,
    new_indicators INTEGER NOT NULL DEFAULT 0,
    rejected       INTEGER NOT NULL DEFAULT 0,
    suppressed     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_iocs_score ON iocs (score);
CREATE INDEX IF NOT EXISTS idx_links_dst ON links (dst_id);
CREATE INDEX IF NOT EXISTS idx_sightings_campaign ON sightings (campaign);
"""


def _decode(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["tags"] = json.loads(item.get("tags") or "[]")
    item["campaigns"] = json.loads(item.get("campaigns") or "[]")
    return item


class Store:
    """Repository over SQLite. Writes are batched; call commit() to persist them."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    # -- writes ----------------------------------------------------------
    def record_sighting(
        self,
        *,
        ioc_type: str,
        value: str,
        source: str,
        confidence: float,
        reliability: float,
        tags: tuple[str, ...],
        campaign: str,
        seen_at,
    ) -> tuple[int, bool]:
        """Store one sighting and refresh the indicator's summary. Returns (ioc_id, created)."""
        seen = to_iso(seen_at)
        row = self.conn.execute(
            "SELECT id FROM iocs WHERE ioc_type = ? AND value = ?", (ioc_type, value)
        ).fetchone()
        created = row is None
        if created:
            ioc_id = self.conn.execute(
                "INSERT INTO iocs (ioc_type, value, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                (ioc_type, value, seen, seen),
            ).lastrowid
        else:
            ioc_id = row["id"]
        self.conn.execute(
            """INSERT INTO sightings (ioc_id, source, campaign, confidence, reliability, seen_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (ioc_id, source, campaign) DO UPDATE SET
                   confidence = MAX(sightings.confidence, excluded.confidence),
                   reliability = excluded.reliability,
                   seen_at = MAX(sightings.seen_at, excluded.seen_at)""",
            (ioc_id, source, campaign, confidence, reliability, seen),
        )
        self._refresh_summary(ioc_id, tags)
        return ioc_id, created

    def _refresh_summary(self, ioc_id: int, tags: tuple[str, ...]) -> None:
        # One contribution per source (its best sighting), then noisy-OR across sources.
        per_source = self.conn.execute(
            """SELECT source, MAX(confidence * reliability) AS contribution,
                      MIN(seen_at) AS first, MAX(seen_at) AS last
               FROM sightings WHERE ioc_id = ? GROUP BY source""",
            (ioc_id,),
        ).fetchall()
        campaigns = [
            r["campaign"]
            for r in self.conn.execute(
                "SELECT DISTINCT campaign FROM sightings WHERE ioc_id = ? AND campaign != ''",
                (ioc_id,),
            )
        ]
        current = self.conn.execute("SELECT tags FROM iocs WHERE id = ?", (ioc_id,)).fetchone()
        merged_tags = sorted(set(json.loads(current["tags"])) | set(tags))
        # Context sightings (confidence 0) are not evidence, so their source is not counted either.
        assessing = [r for r in per_source if r["contribution"] > 0]
        self.conn.execute(
            """UPDATE iocs SET score = ?, first_seen = ?, last_seen = ?, sources = ?,
                              tags = ?, campaigns = ? WHERE id = ?""",
            (
                combine(r["contribution"] for r in per_source),
                min(r["first"] for r in per_source),
                max(r["last"] for r in per_source),
                len(assessing),
                json.dumps(merged_tags),
                json.dumps(sorted(campaigns)),
                ioc_id,
            ),
        )

    def add_link(
        self,
        *,
        src_id: int,
        dst_id: int,
        relation: str,
        origin: str,
        source: str,
        weight: float = 1.0,
        seen_at=None,
    ) -> None:
        if src_id == dst_id:
            return
        self.conn.execute(
            """INSERT INTO links (src_id, dst_id, relation, origin, source, weight, seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (src_id, dst_id, relation, origin, source) DO UPDATE SET
                   weight = MAX(links.weight, excluded.weight),
                   seen_at = excluded.seen_at""",
            (src_id, dst_id, relation, origin, source, weight,
             to_iso(seen_at) if seen_at is not None else None),
        )

    def clear_derived_links(self) -> None:
        """Drop links that are recomputed from indicator values or campaigns. Feed links persist."""
        self.conn.execute("DELETE FROM links WHERE origin IN ('structural', 'cooccurrence')")

    def record_feed_run(self, *, feed: str, fmt: str, reliability: float, last_run: str,
                        status: str, report: dict[str, int]) -> None:
        self.conn.execute(
            """INSERT INTO feed_runs (feed, format, reliability, last_run, status,
                                      accepted, new_indicators, rejected, suppressed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (feed) DO UPDATE SET
                   format = excluded.format, reliability = excluded.reliability,
                   last_run = excluded.last_run, status = excluded.status,
                   accepted = excluded.accepted, new_indicators = excluded.new_indicators,
                   rejected = excluded.rejected, suppressed = excluded.suppressed""",
            (feed, fmt, reliability, last_run, status,
             report.get("accepted", 0), report.get("new_indicators", 0),
             report.get("rejected", 0), report.get("suppressed", 0)),
        )
        self.commit()

    # -- reads -----------------------------------------------------------
    def find_ioc(self, ioc_type: str, value: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM iocs WHERE ioc_type = ? AND value = ?", (ioc_type, value)
        ).fetchone()
        return _decode(row) if row else None

    def get_ioc(self, ioc_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM iocs WHERE id = ?", (ioc_id,)).fetchone()
        return _decode(row) if row else None

    def search(self, *, text: str | None = None, ioc_type: str | None = None,
               min_score: float = 0.0) -> list[dict[str, Any]]:
        # Scores only fall with age, so the stored score is an upper bound for filtering.
        sql = "SELECT * FROM iocs WHERE score >= ?"
        params: list[Any] = [min_score]
        if ioc_type:
            sql += " AND ioc_type = ?"
            params.append(ioc_type)
        if text:
            sql += " AND value LIKE ?"
            params.append(f"%{text.lower()}%")
        return [_decode(r) for r in self.conn.execute(sql, params).fetchall()]

    def links_for(self, ioc_id: int) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM links WHERE src_id = ? OR dst_id = ?", (ioc_id, ioc_id))]

    def all_links(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM links")]

    def ioc_index(self) -> dict[tuple[str, str], int]:
        return {(r["ioc_type"], r["value"]): r["id"]
                for r in self.conn.execute("SELECT id, ioc_type, value FROM iocs")}

    def campaign_members(self) -> dict[str, set[int]]:
        """Every campaign or report group and the indicators in it."""
        out: dict[str, set[int]] = defaultdict(set)
        for r in self.conn.execute(
                "SELECT DISTINCT ioc_id, campaign FROM sightings WHERE campaign != ''"):
            out[r["campaign"]].add(r["ioc_id"])
        return dict(out)

    def feed_campaigns(self) -> dict[int, set[str]]:
        """Campaigns each indicator was reported in by feeds. Report groups are excluded."""
        out: dict[int, set[str]] = defaultdict(set)
        for r in self.conn.execute(
                "SELECT DISTINCT ioc_id, campaign FROM sightings "
                "WHERE campaign != '' AND campaign NOT LIKE ?", (f"{REPORT_PREFIX}%",)):
            out[r["ioc_id"]].add(r["campaign"])
        return dict(out)

    def feed_runs(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM feed_runs ORDER BY feed")]

    def stats(self) -> dict[str, Any]:
        def count(sql: str) -> int:
            return int(self.conn.execute(sql).fetchone()[0])

        by_type = {r["ioc_type"]: r["n"] for r in self.conn.execute(
            "SELECT ioc_type, COUNT(*) AS n FROM iocs GROUP BY ioc_type")}
        return {
            "indicators": count("SELECT COUNT(*) FROM iocs"),
            "sightings": count("SELECT COUNT(*) FROM sightings"),
            "links": count("SELECT COUNT(*) FROM links"),
            "campaigns": len(self.campaign_members()),
            "by_type": by_type,
        }
