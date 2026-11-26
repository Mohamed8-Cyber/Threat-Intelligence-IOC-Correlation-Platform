"""Correlation engine.

Three kinds of link are kept apart on purpose.

  structural    facts computed from indicator values: URL host, parent domain, CIDR membership
  feed          assertions made by a named source, with a timestamp that decays
  cooccurrence  a suggestion that two indicators appear in the same campaign or report

Only structural links and feed links corroborated by at least `min_sources` independent sources
can form clusters. Co-occurrence never does; it is shown to analysts as a suggestion.

An indicator that appears in two or more feed campaigns, or that is linked to more than
`max_fan_in` others, is shared infrastructure. It is listed separately and kept out of clusters,
so that one shared address cannot merge two unrelated campaigns.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from itertools import combinations
from typing import Any

from .models import HASH_TYPES, IOCType, from_iso, utcnow
from .normalize import host_of, host_type, parent_domains
from .scoring import decay
from .storage import Store

RELATION_LABELS = {
    "hosted_on": "URL served from this host",
    "subdomain_of": "subdomain of",
    "email_domain": "mailbox on domain",
    "in_range": "address inside range",
    "resolves_to": "resolves to",
    "downloaded_from": "payload downloaded from",
    "co_reported": "reported together (suggestion)",
    "related_to": "reported alongside",
}

_HOSTS = frozenset({IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6})


def infer_relation(a: IOCType, b: IOCType) -> str:
    """Name the relation between two indicators from their types."""
    kinds = {a, b}
    if len(kinds) == 2:
        if IOCType.DOMAIN in kinds and kinds & {IOCType.IPV4, IOCType.IPV6}:
            return "resolves_to"
        if IOCType.URL in kinds and kinds & _HOSTS:
            return "hosted_on"
        if kinds == {IOCType.EMAIL, IOCType.DOMAIN}:
            return "email_domain"
        if IOCType.CIDR in kinds and kinds & {IOCType.IPV4, IOCType.IPV6}:
            return "in_range"
    hashed, other = (a, b) if a in HASH_TYPES else (b, a)
    if hashed in HASH_TYPES and other not in HASH_TYPES and other in _HOSTS | {IOCType.URL}:
        return "downloaded_from"
    return "related_to"


class Correlator:
    def __init__(self, store: Store, *, half_life_days: float = 30.0,
                 max_campaign_members: int = 100, max_fan_in: int = 10,
                 min_sources: int = 2) -> None:
        self.store = store
        self.half_life_days = half_life_days
        self.max_campaign_members = max_campaign_members
        self.max_fan_in = max_fan_in
        self.min_sources = min_sources

    # -- link derivation -------------------------------------------------
    def refresh(self) -> dict[str, int]:
        """Recompute structural and co-occurrence links. Feed links are left untouched."""
        store = self.store
        store.clear_derived_links()
        index = store.ioc_index()
        counts: Counter[str] = Counter()
        networks = [
            (ipaddress.ip_network(value, strict=False), ioc_id)
            for (kind, value), ioc_id in index.items()
            if kind == IOCType.CIDR.value
        ]

        for (kind_name, value), ioc_id in index.items():
            kind = IOCType(kind_name)
            if kind is IOCType.URL:
                host = host_of(kind, value)
                if host:
                    self._structural(ioc_id, index.get((host_type(host).value, host)),
                                     "hosted_on", counts)
            elif kind is IOCType.DOMAIN:
                for parent in parent_domains(value):
                    self._structural(ioc_id, index.get((IOCType.DOMAIN.value, parent)),
                                     "subdomain_of", counts)
            elif kind is IOCType.EMAIL:
                host = host_of(kind, value)
                self._structural(ioc_id, index.get((IOCType.DOMAIN.value, host)),
                                 "email_domain", counts)
            elif kind in (IOCType.IPV4, IOCType.IPV6):
                addr = ipaddress.ip_address(value)
                for net, net_id in networks:
                    if net.version == addr.version and addr in net:
                        self._structural(ioc_id, net_id, "in_range", counts)

        pair_counts: Counter[tuple[int, int]] = Counter()
        for _campaign, ids in store.campaign_members().items():
            if len(ids) < 2:
                continue
            if len(ids) > self.max_campaign_members:
                counts["oversized_campaigns_skipped"] += 1
                continue
            for pair in combinations(sorted(ids), 2):
                pair_counts[pair] += 1
        for (a, b), shared in pair_counts.items():
            store.add_link(src_id=a, dst_id=b, relation="co_reported", origin="cooccurrence",
                           source="derived", weight=min(1.0, 0.5 * shared))
            counts["co_reported"] += 1

        store.commit()
        return dict(counts)

    def _structural(self, src: int, dst: int | None, relation: str, counts: Counter[str]) -> None:
        if dst is None:
            return
        self.store.add_link(src_id=src, dst_id=dst, relation=relation, origin="structural",
                            source="derived", weight=1.0)
        counts[relation] += 1

    # -- queries ---------------------------------------------------------
    def neighborhood(self, root_id: int, depth: int = 2) -> dict[str, Any]:
        """Breadth-first neighbourhood of an indicator, with the links between its members."""
        depth = max(1, min(depth, 4))
        hops: dict[int, int] = {root_id: 0}
        frontier = [root_id]
        for hop in range(1, depth + 1):
            next_frontier: list[int] = []
            for node in frontier:
                for link in self.store.links_for(node):
                    other = link["dst_id"] if link["src_id"] == node else link["src_id"]
                    if other not in hops:
                        hops[other] = hop
                        next_frontier.append(other)
            frontier = next_frontier

        edges: dict[tuple, dict[str, Any]] = {}
        for node in hops:
            for link in self.store.links_for(node):
                if link["src_id"] in hops and link["dst_id"] in hops:
                    a, b = sorted((link["src_id"], link["dst_id"]))
                    key = (a, b, link["relation"], link["origin"], link["source"])
                    edges.setdefault(key, {
                        "from": link["src_id"], "to": link["dst_id"],
                        "relation": link["relation"], "origin": link["origin"],
                        "source_name": link["source"], "weight": link["weight"],
                    })
        return {"root": root_id, "hops": hops, "edges": list(edges.values())}

    def clusters(self, min_weight: float = 0.3, limit: int = 20) -> dict[str, Any]:
        """Group indicators into clusters, and list the shared infrastructure that was kept out."""
        now = utcnow()
        eligible: dict[tuple[int, int, str], float] = {}
        feed_groups: dict[tuple[int, int, str], dict[str, Any]] = defaultdict(
            lambda: {"sources": set(), "best": 0.0})

        for link in self.store.all_links():
            a, b = sorted((link["src_id"], link["dst_id"]))
            key = (a, b, link["relation"])
            if link["origin"] == "structural":
                eligible[key] = 1.0
            elif link["origin"] == "feed":
                group = feed_groups[key]
                group["sources"].add(link["source"])
                seen = from_iso(link["seen_at"]) if link["seen_at"] else now
                group["best"] = max(group["best"],
                                    decay(link["weight"], seen, now, self.half_life_days))
        for key, group in feed_groups.items():
            if len(group["sources"]) >= self.min_sources:
                eligible[key] = max(eligible.get(key, 0.0), group["best"])
        eligible = {key: weight for key, weight in eligible.items() if weight >= min_weight}

        neighbours: dict[int, set[int]] = defaultdict(set)
        for a, b, _relation in eligible:
            neighbours[a].add(b)
            neighbours[b].add(a)

        feed_campaigns = self.store.feed_campaigns()
        shared: dict[int, list[str]] = {}
        candidates = set(neighbours) | {n for n, c in feed_campaigns.items() if len(c) >= 2}
        for node in candidates:
            reasons: list[str] = []
            campaigns = feed_campaigns.get(node, set())
            if len(campaigns) >= 2:
                reasons.append(f"seen in {len(campaigns)} campaigns: {', '.join(sorted(campaigns))}")
            fan_in = len(neighbours.get(node, ()))
            if fan_in > self.max_fan_in:
                reasons.append(f"linked to {fan_in} indicators")
            if reasons:
                shared[node] = reasons

        parent: dict[int, int] = {}

        def find(x: int) -> int:
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        clean_edges = [(a, b, rel) for a, b, rel in eligible
                       if a not in shared and b not in shared]
        for a, b, _relation in clean_edges:
            root_a, root_b = find(a), find(b)
            if root_a != root_b:
                parent[root_a] = root_b

        members: dict[int, list[int]] = defaultdict(list)
        for node in {n for a, b, _ in clean_edges for n in (a, b)}:
            members[find(node)].append(node)
        relation_counts: dict[int, Counter[str]] = defaultdict(Counter)
        for a, _b, relation in clean_edges:
            relation_counts[find(a)][relation] += 1

        clusters = [
            {"member_ids": sorted(nodes), "relations": dict(relation_counts[root])}
            for root, nodes in members.items() if len(nodes) >= 2
        ]
        clusters.sort(key=lambda c: len(c["member_ids"]), reverse=True)
        shared_list = [
            {"id": node, "reasons": reasons, "neighbours": len(neighbours.get(node, ()))}
            for node, reasons in sorted(shared.items(),
                                        key=lambda kv: -len(neighbours.get(kv[0], ())))
        ]
        return {"clusters": clusters[:limit], "shared_infrastructure": shared_list[:limit]}
