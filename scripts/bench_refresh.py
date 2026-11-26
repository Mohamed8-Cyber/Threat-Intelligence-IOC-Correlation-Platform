"""Measure a full derived-link refresh at increasing sizes. Synthetic data only.

Run:  python scripts/bench_refresh.py 2000 10000 --campaign-size 20 100

The refresh recomputes every structural and co-occurrence link on each ingest, so its cost is
the number that decides when the MVP needs incremental updates. See docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import argparse
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from tip.aggregator import Aggregator
from tip.correlation import Correlator
from tip.feeds import parse
from tip.storage import Store

NOW = datetime.now(timezone.utc)


def make_csv(count: int, campaign_size: int) -> str:
    rows = ["type,value,confidence,tags,campaign,related"]
    for i in range(count):
        address = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
        rows.append(f"domain,host{i}.bench.example,60,c2,camp-{i // campaign_size},{address}")
    return "\n".join(rows) + "\n"


def run(count: int, campaign_size: int) -> dict[str, float]:
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "bench.db")
        aggregator = Aggregator(store, allowlist=(), clock=lambda: NOW)
        correlator = Correlator(store)
        text = make_csv(count, campaign_size)

        started = time.perf_counter()
        aggregator.ingest(parse("csv", text, "bench"), source="bench", reliability=0.8)
        ingest_s = time.perf_counter() - started

        started = time.perf_counter()
        counts = correlator.refresh()
        refresh_s = time.perf_counter() - started

        started = time.perf_counter()
        correlator.clusters(min_weight=0.3, limit=20)
        cluster_s = time.perf_counter() - started
        store.close()
    return {
        "indicators": count,
        "campaign_size": campaign_size,
        "ingest_s": ingest_s,
        "refresh_s": refresh_s,
        "cluster_s": cluster_s,
        "co_reported_links": counts.get("co_reported", 0),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("sizes", nargs="+", type=int)
    parser.add_argument("--campaign-size", nargs="+", type=int, default=[20])
    args = parser.parse_args()

    print(f"{'indicators':>10} {'campaign':>8} {'ingest s':>9} {'refresh s':>10} "
          f"{'cluster s':>10} {'co_reported':>12}")
    for size in args.sizes:
        for campaign in args.campaign_size:
            r = run(size, campaign)
            print(f"{r['indicators']:>10} {r['campaign_size']:>8} {r['ingest_s']:>9.2f} "
                  f"{r['refresh_s']:>10.2f} {r['cluster_s']:>10.3f} {r['co_reported_links']:>12}")


if __name__ == "__main__":
    main()
