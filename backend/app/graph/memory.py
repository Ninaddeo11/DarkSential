"""In-memory GraphStore: offline mode, tests, and deployments without Neo4j.

Mirrors Neo4jGraphStore semantics (same projection, provenance merge, aging
and path rules) so the contract tests can run against both.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from app.graph.project import NON_TRAVERSABLE_LABELS, TERMINAL_LABELS, THREAT_LABELS, GraphBatch
from app.graph.store import (
    AgingStats,
    CpeCandidate,
    CveMatch,
    RawPath,
    RelatedThreat,
    TechniqueRef,
    UpsertStats,
    filter_cpe_candidates,
    merge_related,
    observable_keys_for_ioc,
    select_best_paths,
)


@dataclass
class _Node:
    id: str
    label: str
    props: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    sources: set[str] = field(default_factory=set)
    confidence: int | None = None
    ttl_days: int | None = None
    stale: bool = False

    def view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "name": self.props.get("name"),
            "external_id": self.props.get("external_id"),
            "confidence": self.confidence,
            "sources": sorted(self.sources),
            "stale": self.stale,
        }


@dataclass
class _Edge:
    id: str
    src: str
    tgt: str
    rel_type: str
    sources: set[str] = field(default_factory=set)
    confidence: int | None = None


class InMemoryGraphStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: dict[str, _Node] = {}
        self._edges: dict[str, _Edge] = {}
        self._observables: dict[str, set[str]] = defaultdict(set)  # key -> indicator ids
        self._cpes: dict[str, dict[str, Any]] = {}  # criteria -> props
        self._affects: dict[tuple[str, str], dict[str, str]] = {}  # (vuln, criteria) -> range
        self._rules: dict[str, dict[str, Any]] = {}  # rule_id -> {rationale, techniques}

    # --- lifecycle --------------------------------------------------------------------

    def ensure_schema(self) -> None:
        return None

    def ping(self) -> None:
        return None

    def close(self) -> None:
        return None

    # --- writes -----------------------------------------------------------------------

    def upsert(
        self,
        batch: GraphBatch,
        *,
        source: str,
        confidence: int,
        ttl_days: int | None,
        seen_at: datetime,
    ) -> UpsertStats:
        stats = UpsertStats()
        with self._lock:
            for rec in batch.nodes:
                node_conf = rec.confidence if rec.confidence is not None else confidence
                node = self._nodes.get(rec.id)
                if node is None:
                    node = _Node(rec.id, rec.label, {}, seen_at, seen_at)
                    self._nodes[rec.id] = node
                node.props.update(rec.props)
                node.last_seen = max(node.last_seen, seen_at)
                node.sources.add(source)
                node.confidence = max(node.confidence or 0, node_conf)
                node.stale = False
                if rec.label == "Indicator":
                    node.ttl_days = ttl_days
                stats.nodes += 1
            for edge in batch.edges:
                if edge.src not in self._nodes or edge.tgt not in self._nodes:
                    stats.skipped_edges += 1
                    continue
                existing = self._edges.setdefault(
                    edge.id, _Edge(edge.id, edge.src, edge.tgt, edge.rel_type)
                )
                existing.sources.add(source)
                edge_conf = edge.confidence if edge.confidence is not None else confidence
                existing.confidence = max(existing.confidence or 0, edge_conf)
                stats.edges += 1
            for obs in batch.observables:
                self._observables[obs.key].add(obs.indicator_id)
                stats.observables += 1
            for cpe in batch.cpes:
                self._cpes[cpe.criteria] = {
                    "part": cpe.part,
                    "vendor": cpe.vendor,
                    "product": cpe.product,
                    "version": cpe.version,
                }
                self._affects[(cpe.vulnerability_id, cpe.criteria)] = dict(cpe.range)
                stats.cpes += 1
            for mention in batch.mentions:
                for target in self._mention_targets(mention.technique_id, mention.name_key):
                    edge_id = f"{mention.report_id}|mentions|{target}"
                    self._edges.setdefault(
                        edge_id, _Edge(edge_id, mention.report_id, target, "MENTIONS")
                    ).sources.add(source)
                    stats.mentions += 1
        return stats

    def _mention_targets(self, technique_id: str | None, key: str | None) -> list[str]:
        named = {"Malware", "Tool", "IntrusionSet", "Campaign"}
        return [
            node.id
            for node in self._nodes.values()
            if (
                technique_id
                and node.label == "AttackPattern"
                and node.props.get("external_id") == technique_id
            )
            or (key and node.label in named and key in node.props.get("alias_keys", []))
        ]

    def age_indicators(self, now: datetime) -> AgingStats:
        stats = AgingStats()
        with self._lock:
            for node in list(self._nodes.values()):
                if node.label != "Indicator" or not node.ttl_days:
                    continue
                age = now - node.last_seen
                if age > timedelta(days=2 * node.ttl_days):
                    self._delete_node(node.id)
                    stats.purged += 1
                elif age > timedelta(days=node.ttl_days) and not node.stale:
                    node.stale = True
                    stats.stale += 1
        return stats

    def _delete_node(self, node_id: str) -> None:
        self._nodes.pop(node_id, None)
        for edge_id in [e.id for e in self._edges.values() if node_id in (e.src, e.tgt)]:
            del self._edges[edge_id]
        for key in list(self._observables):
            self._observables[key].discard(node_id)
            if not self._observables[key]:
                del self._observables[key]

    def link_rule(self, rule_id: str, technique_ids: Sequence[str], rationale: str) -> list[str]:
        with self._lock:
            found: list[str] = []
            missing: list[str] = []
            for tid in technique_ids:
                node = self._technique(tid)
                (found if node else missing).append(tid)
            self._rules[rule_id] = {"rationale": rationale, "techniques": found}
            return missing

    def _technique(self, external_id: str) -> _Node | None:
        for node in self._nodes.values():
            if node.label == "AttackPattern" and node.props.get("external_id") == external_id:
                return node
        return None

    # --- reads ------------------------------------------------------------------------

    def related_threats(self, ioc: str, max_hops: int = 3) -> list[RelatedThreat]:
        results: list[RelatedThreat] = []
        with self._lock:
            for key in observable_keys_for_ioc(ioc):
                for ind_id in sorted(self._observables.get(key, ())):
                    indicator = self._nodes[ind_id]
                    paths = list(self._paths_from(ind_id, max_hops))
                    results.extend(select_best_paths(indicator.view(), paths, THREAT_LABELS))
        return merge_related(results)

    def _adjacent(self, node_id: str) -> Iterator[tuple[_Edge, str]]:
        for edge in self._edges.values():
            if edge.src == node_id:
                yield edge, edge.tgt
            elif edge.tgt == node_id:
                yield edge, edge.src

    def _paths_from(self, start: str, max_hops: int) -> Iterator[RawPath]:
        """All relationship-unique paths of 1..max_hops, honoring traversal rules."""

        def walk(nodes: list[str], rels: list[str], used: set[str]) -> Iterator[RawPath]:
            if rels:
                yield RawPath(tuple(self._nodes[n].view() for n in nodes), tuple(rels))
            if len(rels) >= max_hops:
                return
            current = self._nodes[nodes[-1]]
            if len(nodes) > 1 and current.label in TERMINAL_LABELS:
                return
            for edge, other in self._adjacent(current.id):
                if edge.id in used or other not in self._nodes:
                    continue
                if self._nodes[other].label in NON_TRAVERSABLE_LABELS:
                    continue
                yield from walk([*nodes, other], [*rels, edge.rel_type], used | {edge.id})

        yield from walk([start], [], set())

    def cves_for_cpe(self, cpe: str) -> list[CveMatch]:
        from app.graph.cpe import Cpe

        target = Cpe.parse(cpe)
        with self._lock:
            candidates = [
                CpeCandidate(
                    vulnerability={"id": vid, **self._nodes[vid].props},
                    criteria=criteria,
                    range=rng,
                )
                for (vid, criteria), rng in self._affects.items()
                if vid in self._nodes
                and self._cpes[criteria]["vendor"] == target.vendor
                and self._cpes[criteria]["product"] == target.product
            ]
        return filter_cpe_candidates(cpe, candidates)

    def techniques_for_behavior(self, rule_id: str) -> list[TechniqueRef]:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None:
                return []
            refs = []
            for tid in rule["techniques"]:
                node = self._technique(tid)
                if node:
                    refs.append(
                        TechniqueRef(
                            external_id=tid,
                            name=node.props.get("name"),
                            tactics=list(node.props.get("tactics", [])),
                            stix_id=node.id,
                        )
                    )
            return sorted(refs, key=lambda r: r.external_id)

    def named_entities(self) -> list[tuple[str, str, list[str]]]:
        with self._lock:
            out = []
            for node in self._nodes.values():
                if node.label in {"Malware", "Tool", "IntrusionSet", "Campaign"}:
                    name = node.props.get("name")
                    if name:
                        aliases = list(node.props.get("aliases", []))
                        out.append((node.props["stix_type"], name, aliases))
            return sorted(out)

    def technique_ids(self) -> set[str]:
        with self._lock:
            return {
                n.props["external_id"]
                for n in self._nodes.values()
                if n.label == "AttackPattern" and n.props.get("external_id")
            }

    def counts(self) -> dict[str, int]:
        with self._lock:
            out: dict[str, int] = defaultdict(int)
            for node in self._nodes.values():
                out[node.label] += 1
            if self._observables:
                out["Observable"] = len(self._observables)
            if self._cpes:
                out["CPE"] = len(self._cpes)
            if self._rules:
                out["DetectionRule"] = len(self._rules)
            out["relationships"] = len(self._edges)
            return dict(sorted(out.items()))

    def node(self, node_id: str) -> dict[str, Any] | None:
        """Test/debug helper: node props plus provenance."""
        with self._lock:
            n = self._nodes.get(node_id)
            if n is None:
                return None
            return {
                **n.props,
                **n.view(),
                "first_seen": n.first_seen,
                "last_seen": n.last_seen,
                "ttl_days": n.ttl_days,
            }
