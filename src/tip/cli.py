"""Command-line interface: `tip <command>`."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from . import __version__
from .config import Settings
from .models import IOCType
from .service import EXPORT_FORMATS, TIPService


def _table(headers: list[str], rows: list[list[Any]]) -> None:
    cells = [[str(c) for c in row] for row in rows]
    widths = [max([len(h)] + [len(row[i]) for row in cells]) for i, h in enumerate(headers)]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for row in cells:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))


def _print_report(name: str, report: dict[str, Any]) -> None:
    derived = report.get("derived_links", {})
    print(f"  {name}: accepted={report['accepted']} new={report['new_indicators']} "
          f"rejected={report['rejected']} suppressed={report['suppressed']} "
          f"feed_links={report['links_added']} "
          f"co_reported={derived.get('co_reported', 0)} "
          f"oversized_campaigns_skipped={derived.get('oversized_campaigns_skipped', 0)}")


def _print_clusters(result: dict[str, Any]) -> None:
    if not result["clusters"]:
        print("No corroborated clusters at this threshold.")
    for index, cluster in enumerate(result["clusters"], start=1):
        campaigns = ", ".join(cluster["campaigns"]) or "-"
        reports = ", ".join(cluster["reports"]) or "-"
        print(f"\nCluster {index}: {cluster['size']} indicators, "
              f"top triage score {cluster['max_score']:.0%}")
        print(f"  campaigns: {campaigns}   reports: {reports}")
        for member in cluster["members"][:8]:
            print(f"  {member['type']:<8} {member['value']:<48} {member['score']:.0%}  "
                  f"{member['severity']}")
    if result["shared_infrastructure"]:
        print("\nShared infrastructure (kept out of clusters):")
        for item in result["shared_infrastructure"]:
            print(f"  {item['type']:<8} {item['value']:<20} {'; '.join(item['reasons'])}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tip", description="Threat intelligence aggregation and IOC correlation.")
    parser.add_argument("--version", action="version", version=f"tip {__version__}")
    parser.add_argument("--db", help="SQLite database path (default: $TIP_DB_PATH or tip.db)")
    parser.add_argument("--feeds", help="feeds.json path (default: $TIP_FEEDS_FILE)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="load the bundled sample feeds and analyst report, then summarize")

    feed = sub.add_parser("feed", help="list or run configured feeds")
    feed_sub = feed.add_subparsers(dest="feed_command", required=True)
    feed_sub.add_parser("list", help="show configured feeds and their last run")
    run = feed_sub.add_parser("run", help="run one configured feed")
    run.add_argument("name")

    ingest = sub.add_parser("ingest", help="ingest a local file")
    ingest.add_argument("file")
    ingest.add_argument("--format", choices=["text", "csv", "stix"], default="text")
    ingest.add_argument("--source", required=True)
    ingest.add_argument("--reliability", type=float, default=0.5)

    report = sub.add_parser("report", help="extract indicators from an analyst report")
    report.add_argument("file")
    report.add_argument("--source", default="analyst")
    report.add_argument("--title", help="report title; used to group the indicators")
    report.add_argument("--reliability", type=float, default=0.7)

    search = sub.add_parser("search", help="search indicators by value")
    search.add_argument("query", nargs="?")
    search.add_argument("--type", choices=[t.value for t in IOCType])
    search.add_argument("--min-score", type=float, default=0.0)
    search.add_argument("--limit", type=int, default=20)

    lookup = sub.add_parser("lookup", help="show one indicator as JSON")
    lookup.add_argument("type", choices=[t.value for t in IOCType])
    lookup.add_argument("value")

    correlate = sub.add_parser("correlate", help="show the neighbourhood of one indicator")
    correlate.add_argument("type", choices=[t.value for t in IOCType])
    correlate.add_argument("value")
    correlate.add_argument("--depth", type=int, default=2)

    clusters = sub.add_parser("clusters", help="list corroborated clusters and shared infrastructure")
    clusters.add_argument("--min-weight", type=float, default=None)
    clusters.add_argument("--limit", type=int, default=10)

    export = sub.add_parser("export", help="export indicators")
    export.add_argument("format", choices=EXPORT_FORMATS)
    export.add_argument("--out", required=True)
    export.add_argument("--type", choices=[t.value for t in IOCType])
    export.add_argument("--min-score", type=float, default=0.0)

    serve = sub.add_parser("serve", help="run the HTTP API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser


def _demo(service: TIPService) -> int:
    samples = Path(service.settings.feeds_file).parent
    print(f"Ingesting {len(service.feed_specs())} configured feeds into {service.settings.db_path}")
    for spec in service.feed_specs():
        _print_report(spec.name, service.run_feed(spec.name))
    report_path = samples / "analyst_report.txt"
    if report_path.exists():
        _print_report("analyst-report", service.ingest_report(
            text=report_path.read_text(encoding="utf-8"), source="analyst-report",
            title="INC-2026-1022 payroll beacon", reliability=0.7))

    stats = service.stats()
    print(f"\nIndicators: {stats['indicators']}   sightings: {stats['sightings']}   "
          f"links: {stats['links']}   campaigns: {stats['campaigns']}")
    _table(["Type", "Count"], sorted(stats["by_type"].items()))
    _print_clusters(service.clusters(limit=10))
    return 0


def _run(args: argparse.Namespace, service: TIPService) -> int:
    if args.command == "demo":
        return _demo(service)

    if args.command == "feed":
        if args.feed_command == "list":
            _table(["Name", "Format", "Reliability", "Last run", "Status"],
                   [[f["name"], f["format"], f["reliability"], f["last_run"] or "-", f["status"]]
                    for f in service.feeds()])
            return 0
        _print_report(args.name, service.run_feed(args.name))
        return 0

    if args.command == "ingest":
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        _print_report(args.source, service.ingest_payload(
            text=text, source=args.source, format_name=args.format,
            reliability=args.reliability))
        return 0

    if args.command == "report":
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        _print_report(args.source, service.ingest_report(
            text=text, source=args.source, title=args.title, reliability=args.reliability))
        return 0

    if args.command == "search":
        items = service.search(text=args.query, ioc_type=args.type,
                               min_score=args.min_score, limit=args.limit)
        _table(["Type", "Value", "Triage", "Severity", "Sources", "Campaigns"],
               [[i["type"], i["value"], f"{i['score']:.0%}", i["severity"], i["sources"],
                 ",".join(i["campaigns"]) or "-"] for i in items])
        return 0

    if args.command == "lookup":
        item = service.lookup(args.type, args.value)
        if item is None:
            print("not found", file=sys.stderr)
            return 1
        print(json.dumps(item, indent=2))
        return 0

    if args.command == "correlate":
        result = service.investigate(args.type, args.value, args.depth)
        if result is None:
            print("not found", file=sys.stderr)
            return 1
        names = {node["id"]: node["value"] for node in result["nodes"]}
        root = result["root"]
        print(f"{root['type']} {root['value']}  triage {root['score']:.0%}  {root['severity']}")
        for node in result["nodes"]:
            if node["hop"]:
                print(f"  hop {node['hop']}: {node['type']} {node['value']}  ({node['score']:.0%})")
        for edge in result["edges"]:
            origin = "structural" if edge["origin"] == "structural" else (
                f"feed:{edge['source_name']}" if edge["origin"] == "feed" else "suggestion")
            print(f"  {names.get(edge['from'], edge['from'])} -[{edge['relation']}]-> "
                  f"{names.get(edge['to'], edge['to'])}  ({origin}, weight {edge['weight']:.2f})")
        return 0

    if args.command == "clusters":
        _print_clusters(service.clusters(min_weight=args.min_weight, limit=args.limit))
        return 0

    if args.command == "export":
        out = Path(args.out)
        result = service.export(args.format, ioc_type=args.type, min_score=args.min_score,
                                path=out if args.format == "xlsx" else None)
        if isinstance(result, Path):
            print(f"wrote {result}")
        else:
            out.write_text(result, encoding="utf-8")
            print(f"wrote {out} ({len(result)} bytes)")
        return 0

    raise ValueError(f"unknown command {args.command!r}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings.from_env()
    if args.db:
        settings = replace(settings, db_path=args.db)
    if args.feeds:
        settings = replace(settings, feeds_file=args.feeds)

    if args.command == "serve":
        import secrets

        import uvicorn

        from .api import create_app

        if not settings.api_key:
            # Write endpoints are never open by default. Set TIP_API_KEY to choose the key.
            generated = secrets.token_urlsafe(24)
            settings = replace(settings, api_key=generated)
            print("TIP_API_KEY is not set. Write endpoints accept this generated key "
                  f"for this run only: {generated}", file=sys.stderr)
        uvicorn.run(create_app(settings), host=args.host, port=args.port)
        return 0

    if args.command == "demo" and not args.db:
        settings = replace(settings, db_path="tip-demo.db")
        Path(settings.db_path).unlink(missing_ok=True)

    service = TIPService(settings)
    try:
        return _run(args, service)
    except (ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        service.close()
