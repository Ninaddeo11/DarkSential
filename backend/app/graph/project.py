"""Project validated STIX 2.1 dicts onto graph records (store-agnostic).

Model
-----
(:StixObject:<Label> {id, ...})        one node per STIX SDO we keep
(a)-[:<REL_TYPE> {id}]->(b)            STIX relationship SROs; Report object_refs as REFERS_TO
(:Indicator)-[:OBSERVES]->(:Observable {key, type, value})
(:Vulnerability)-[:AFFECTS {range}]->(:CPE {criteria, part, vendor, product, version})
(:Report)-[:MENTIONS]->(:AttackPattern | named threat)   NLP-derived links
(:DetectionRule {rule_id})-[:DETECTS]->(:AttackPattern)   behavior-rule mapping

Relationship types come from STIX ``relationship_type`` and are interpolated
into Cypher, so they are strictly whitelisted by regex here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.graph.cpe import Cpe
from app.intel.sanitize import excerpt

LABELS: dict[str, str] = {
    "attack-pattern": "AttackPattern",
    "malware": "Malware",
    "tool": "Tool",
    "intrusion-set": "IntrusionSet",
    "campaign": "Campaign",
    "vulnerability": "Vulnerability",
    "indicator": "Indicator",
    "report": "Report",
    "identity": "Identity",
    "course-of-action": "CourseOfAction",
}
ALL_LABELS = frozenset(LABELS.values())
THREAT_LABELS = frozenset(
    {"Malware", "Tool", "IntrusionSet", "Campaign", "AttackPattern", "Vulnerability", "Report"}
)
# Paths may end at, but never pass through, these nodes (hubs that would link
# unrelated threats: a shared technique or CVE is not attribution).
TERMINAL_LABELS = frozenset({"AttackPattern", "Vulnerability", "CourseOfAction"})
NON_TRAVERSABLE_LABELS = frozenset({"Identity"})
_REL_TYPE = re.compile(r"^[a-z][a-z-]{0,40}$")


def rel_type_for(relationship_type: str) -> str:
    if not _REL_TYPE.fullmatch(relationship_type):
        return "RELATED_TO"
    return relationship_type.upper().replace("-", "_")


@dataclass
class NodeRecord:
    id: str
    label: str
    props: dict[str, Any]
    confidence: int | None


@dataclass
class EdgeRecord:
    id: str
    src: str
    tgt: str
    rel_type: str
    confidence: int | None


@dataclass
class ObservableLink:
    indicator_id: str
    key: str
    type: str
    value: str


@dataclass
class CpeLink:
    vulnerability_id: str
    criteria: str
    part: str
    vendor: str
    product: str
    version: str
    range: dict[str, str]


@dataclass
class MentionLink:
    report_id: str
    technique_id: str | None = None  # ATT&CK external id
    name_key: str | None = None  # casefolded threat name


@dataclass
class GraphBatch:
    nodes: list[NodeRecord] = field(default_factory=list)
    edges: list[EdgeRecord] = field(default_factory=list)
    observables: list[ObservableLink] = field(default_factory=list)
    cpes: list[CpeLink] = field(default_factory=list)
    mentions: list[MentionLink] = field(default_factory=list)
    skipped: int = 0


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") in {"mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"}:
            return str(ref["external_id"])
    return None


def _name_keys(obj: dict[str, Any]) -> list[str]:
    names = [obj.get("name"), *(obj.get("aliases") or []), *(obj.get("x_mitre_aliases") or [])]
    return sorted({re.sub(r"\s+", " ", n).strip().casefold() for n in names if isinstance(n, str)})


def _node_props(obj: dict[str, Any], label: str) -> dict[str, Any]:
    props: dict[str, Any] = {
        "stix_type": obj["type"],
        "name": obj.get("name"),
        "name_key": _name_keys({"name": obj.get("name")})[0] if obj.get("name") else None,
        "alias_keys": _name_keys(obj),
        "aliases": sorted(
            {
                a
                for a in [*(obj.get("aliases") or []), *(obj.get("x_mitre_aliases") or [])]
                if isinstance(a, str) and a != obj.get("name")
            }
        ),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "revoked": bool(obj.get("revoked", False)),
        "description": excerpt(obj["description"], 4000) if obj.get("description") else None,
        "stix_json": json.dumps(obj, sort_keys=True),
    }
    if label == "AttackPattern":
        props["external_id"] = _external_id(obj)
        props["tactics"] = sorted({p["phase_name"] for p in obj.get("kill_chain_phases", []) or []})
        props["platforms"] = sorted(obj.get("x_mitre_platforms", []) or [])
        props["is_subtechnique"] = bool(obj.get("x_mitre_is_subtechnique", False))
    elif label in {"Malware", "Tool", "IntrusionSet", "Campaign"}:
        props["external_id"] = _external_id(obj)
    elif label == "Vulnerability":
        props["cve"] = obj["name"]
        cvss = obj.get("x_dsn_cvss") or {}
        props["cvss_score"] = cvss.get("base_score")
        props["cvss_severity"] = cvss.get("base_severity")
        props["cvss_vector"] = cvss.get("vector")
        kev = obj.get("x_dsn_kev")
        if kev:
            props["kev"] = True
            props["kev_date_added"] = kev.get("date_added")
            props["kev_due_date"] = kev.get("due_date")
            props["kev_ransomware"] = kev.get("ransomware") == "Known"
    elif label == "Indicator":
        props["pattern"] = obj.get("pattern")
        props["valid_from"] = obj.get("valid_from")
        props["valid_until"] = obj.get("valid_until")
        props["port"] = obj.get("x_dsn_port")
    elif label == "Report":
        props["published"] = obj.get("published")
    # Never overwrite data from another source with nulls.
    return {k: v for k, v in props.items() if v is not None}


def project(objects: list[dict[str, Any]]) -> GraphBatch:
    batch = GraphBatch()
    for obj in objects:
        otype = obj.get("type")
        if otype == "relationship":
            batch.edges.append(
                EdgeRecord(
                    id=obj["id"],
                    src=obj["source_ref"],
                    tgt=obj["target_ref"],
                    rel_type=rel_type_for(obj["relationship_type"]),
                    confidence=obj.get("confidence"),
                )
            )
            continue
        label = LABELS.get(str(otype))
        if label is None or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            batch.skipped += 1
            continue
        batch.nodes.append(
            NodeRecord(obj["id"], label, _node_props(obj, label), obj.get("confidence"))
        )
        if label == "Indicator":
            for o in obj.get("x_dsn_observables", []) or []:
                batch.observables.append(
                    ObservableLink(obj["id"], f"{o['type']}:{o['value']}", o["type"], o["value"])
                )
        elif label == "Vulnerability":
            for rule in obj.get("x_dsn_cpe_matches", []) or []:
                try:
                    cpe = Cpe.parse(rule["criteria"])
                except (KeyError, ValueError):
                    continue
                rng = {k: str(v) for k, v in rule.items() if k.startswith("version_") and v}
                batch.cpes.append(
                    CpeLink(
                        obj["id"],
                        rule["criteria"],
                        cpe.part,
                        cpe.vendor,
                        cpe.product,
                        cpe.version,
                        rng,
                    )
                )
        elif label == "Report":
            for ref in obj.get("object_refs", []) or []:
                batch.edges.append(
                    EdgeRecord(f"{obj['id']}|refers|{ref}", obj["id"], ref, "REFERS_TO", None)
                )
            for tid in obj.get("x_dsn_technique_ids", []) or []:
                batch.mentions.append(MentionLink(obj["id"], technique_id=str(tid)))
            for name in obj.get("x_dsn_threat_names", []) or []:
                batch.mentions.append(MentionLink(obj["id"], name_key=str(name).casefold()))
    return batch
