"""Graph store contract, result models and shared query logic.

Two implementations satisfy :class:`GraphStore`: ``InMemoryGraphStore`` (tests,
offline dev, no Neo4j configured) and ``Neo4jGraphStore``. Path selection and
CPE filtering live here so both return identical answers; the contract test
suite runs against both.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel

from app.graph.cpe import Cpe, CpeMatchRule
from app.graph.project import GraphBatch

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DEFANG = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I)


# --- Results -------------------------------------------------------------------------


class PathStep(BaseModel):
    node_id: str
    label: str
    name: str | None
    via: str | None  # relationship type used to reach this node (None for the start)


class RelatedThreat(BaseModel):
    threat_id: str
    label: str
    name: str | None
    external_id: str | None
    hops: int
    confidence: float  # weakest link along the path, 0-1
    sources: list[str]
    indicator_id: str
    indicator_stale: bool
    path: list[PathStep]


class CveMatch(BaseModel):
    cve: str
    vulnerability_id: str
    cvss_score: float | None
    cvss_severity: str | None
    kev: bool
    kev_ransomware: bool
    kev_due_date: str | None
    criteria: str
    match: str  # exact | range | unversioned | any-version


class TechniqueRef(BaseModel):
    external_id: str
    name: str | None
    tactics: list[str]
    stix_id: str


class UpsertStats(BaseModel):
    nodes: int = 0
    edges: int = 0
    skipped_edges: int = 0
    observables: int = 0
    cpes: int = 0
    mentions: int = 0


class AgingStats(BaseModel):
    stale: int = 0
    purged: int = 0


@dataclass(frozen=True)
class RawPath:
    """A path as returned by a store: alternating nodes and the rel types between them."""

    nodes: tuple[dict[str, Any], ...]  # each: id, label, name, external_id, confidence, sources
    rels: tuple[str, ...]


@dataclass(frozen=True)
class CpeCandidate:
    vulnerability: dict[str, Any]
    criteria: str
    range: dict[str, str]


# --- Contract ------------------------------------------------------------------------


class GraphStore(Protocol):
    def ensure_schema(self) -> None: ...

    def ping(self) -> None: ...

    def close(self) -> None: ...

    def upsert(
        self,
        batch: GraphBatch,
        *,
        source: str,
        confidence: int,
        ttl_days: int | None,
        seen_at: datetime,
    ) -> UpsertStats: ...

    def age_indicators(self, now: datetime) -> AgingStats: ...

    def related_threats(self, ioc: str, max_hops: int = 3) -> list[RelatedThreat]: ...

    def related_from_node(self, node_id: str, max_hops: int = 3) -> list[RelatedThreat]:
        """Threats reachable from any STIX node (e.g. a CVE), same path rules."""
        ...

    def indicators_for(self, ioc: str) -> list[dict[str, Any]]:
        """Indicators observing an IOC: id, name, confidence, sources, stale, pattern."""
        ...

    def node_by_name(self, label: str, name: str) -> str | None: ...

    def cves_for_cpe(self, cpe: str) -> list[CveMatch]: ...

    def link_rule(self, rule_id: str, technique_ids: Sequence[str], rationale: str) -> list[str]:
        """Map a behavior rule to ATT&CK techniques. Returns IDs not found in the graph."""
        ...

    def techniques_for_behavior(self, rule_id: str) -> list[TechniqueRef]: ...

    def named_entities(self) -> list[tuple[str, str, list[str]]]:
        """(stix_type, name, aliases) for malware / tools / intrusion sets / campaigns."""
        ...

    def technique_ids(self) -> set[str]: ...

    def counts(self) -> dict[str, int]: ...


# --- Shared logic --------------------------------------------------------------------


def observable_keys_for_ioc(ioc: str) -> list[str]:
    """Normalize a user-supplied IOC into candidate Observable keys."""
    value = _DEFANG.sub(".", ioc.strip())
    value = re.sub(r"^hxxp", "http", value, flags=re.I)
    if not value:
        raise ValueError("empty IOC")
    if "://" in value:
        return [f"url:{value}"]
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        pass
    else:
        return [f"{'ipv4-addr' if ip.version == 4 else 'ipv6-addr'}:{ip.compressed}"]
    if _HEX.fullmatch(value) and len(value) in (32, 40, 64):
        kind = {32: "file-md5", 40: "file-sha1", 64: "file-sha256"}[len(value)]
        return [f"{kind}:{value.lower()}"]
    return [f"domain-name:{value.lower().rstrip('.')}"]


HOP_DECAY = 0.85


def _path_confidence(path: RawPath) -> float:
    """Weakest node confidence, decayed by HOP_DECAY for each hop beyond the first.

    Each extra hop is weaker evidence (a co-mention of a co-mention), so a
    3-hop link never outranks an equally sourced direct one.
    """
    values = [n.get("confidence") for n in path.nodes]
    known = [float(v) for v in values if isinstance(v, int | float)]
    if not known:
        return 0.0
    return round(min(known) / 100 * HOP_DECAY ** max(0, len(path.rels) - 1), 3)


def merge_related(results: Iterable[RelatedThreat]) -> list[RelatedThreat]:
    """One result per threat across all matching indicators.

    Deduplicates by (label, casefolded name): feeds name the same family under
    different STIX IDs (e.g. ThreatFox "QakBot" vs ATT&CK QakBot), and the
    analyst-facing answer is the threat, not each node. The best path wins
    (fewest hops, then highest confidence); its node IDs remain in ``path``.
    """
    best: dict[tuple[str, str], RelatedThreat] = {}
    for r in sorted(results, key=lambda r: (r.hops, -r.confidence, r.threat_id)):
        key = (r.label, (r.name or r.threat_id).casefold())
        best.setdefault(key, r)
    return sorted(best.values(), key=lambda r: (r.hops, -r.confidence, r.label, r.name or ""))


def select_best_paths(
    indicator: dict[str, Any], paths: Iterable[RawPath], threat_labels: frozenset[str]
) -> list[RelatedThreat]:
    """Pick one path per reachable threat: fewest hops, then highest confidence, then ids."""
    best: dict[str, tuple[tuple[int, float, tuple[str, ...]], RawPath]] = {}
    for path in paths:
        target = path.nodes[-1]
        if target["label"] not in threat_labels or target["id"] == indicator["id"]:
            continue
        rank = (len(path.rels), -_path_confidence(path), tuple(n["id"] for n in path.nodes))
        current = best.get(target["id"])
        if current is None or rank < current[0]:
            best[target["id"]] = (rank, path)

    results: list[RelatedThreat] = []
    for _, path in sorted(best.values(), key=lambda item: item[0]):
        target = path.nodes[-1]
        steps = [
            PathStep(
                node_id=n["id"],
                label=n["label"],
                name=n.get("name"),
                via=None if i == 0 else path.rels[i - 1],
            )
            for i, n in enumerate(path.nodes)
        ]
        results.append(
            RelatedThreat(
                threat_id=target["id"],
                label=target["label"],
                name=target.get("name"),
                external_id=target.get("external_id"),
                hops=len(path.rels),
                confidence=_path_confidence(path),
                sources=sorted({s for n in path.nodes for s in n.get("sources") or []}),
                indicator_id=indicator["id"],
                indicator_stale=bool(indicator.get("stale", False)),
                path=steps,
            )
        )
    return results


def filter_cpe_candidates(cpe: str, candidates: Iterable[CpeCandidate]) -> list[CveMatch]:
    target = Cpe.parse(cpe)
    rank = {"exact": 0, "range": 1, "unversioned": 2, "any-version": 3}
    best: dict[str, CveMatch] = {}
    for cand in candidates:
        rule = CpeMatchRule.from_props({"criteria": cand.criteria, **cand.range})
        how = rule.match(target)
        if how is None:
            continue
        v = cand.vulnerability
        match = CveMatch(
            cve=v["cve"],
            vulnerability_id=v["id"],
            cvss_score=v.get("cvss_score"),
            cvss_severity=v.get("cvss_severity"),
            kev=bool(v.get("kev", False)),
            kev_ransomware=bool(v.get("kev_ransomware", False)),
            kev_due_date=v.get("kev_due_date"),
            criteria=cand.criteria,
            match=how,
        )
        current = best.get(match.cve)
        if current is None or rank[how] < rank[current.match]:
            best[match.cve] = match
    return sorted(
        best.values(), key=lambda m: (not m.kev, -(m.cvss_score or 0.0), rank[m.match], m.cve)
    )
