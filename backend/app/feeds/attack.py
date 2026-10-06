"""MITRE ATT&CK (STIX 2.1 bundles from mitre-attack/attack-stix-data).

Format verified 2026-10-02: enterprise-attack.json / ics-attack.json are
STIX 2.1 bundles (no bundle-level spec_version) containing attack-pattern,
malware, tool, intrusion-set, campaign, course-of-action, relationship and
x-mitre-* custom objects.

Kept: the SDO types the graph models plus relationships. Dropped: x-mitre-*
objects, revoked or deprecated objects, and relationships touching them.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.feeds.base import Candidate, FeedAdapter, Rejection

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
)
KEEP_TYPES = frozenset(
    {
        "attack-pattern",
        "malware",
        "tool",
        "intrusion-set",
        "campaign",
        "course-of-action",
        "relationship",
    }
)
ALLOWED_DOMAINS = frozenset({"enterprise-attack", "ics-attack", "mobile-attack"})


class MitreAttackAdapter(FeedAdapter):
    name = "mitre_attack"

    def fetch(self) -> Any:
        domains = self.ctx.config.options.get("domains", ["enterprise-attack"])
        bundles = []
        for domain in domains:
            if domain not in ALLOWED_DOMAINS:
                raise ValueError(f"unknown ATT&CK domain {domain!r}")
            bundles.append(self._fetcher().fetch_json(ATTACK_URL.format(domain=domain)))
        return bundles

    def candidates(self, raw: Any) -> Iterable[Candidate | Rejection]:
        bundles = raw if isinstance(raw, list) else [raw]
        objects = [o for b in bundles for o in b.get("objects", [])]
        dropped = {
            o["id"]
            for o in objects
            if o.get("type") not in KEEP_TYPES or o.get("revoked") or o.get("x_mitre_deprecated")
        }
        for obj in objects:
            if obj["id"] in dropped:
                continue
            if obj["type"] == "relationship" and (
                obj.get("source_ref") in dropped or obj.get("target_ref") in dropped
            ):
                continue
            # ATT&CK's created_by_ref / markings point at objects we don't keep;
            # provenance is tracked by the graph layer instead.
            yield {
                k: v
                for k, v in obj.items()
                if k not in {"created_by_ref", "object_marking_refs", "x_mitre_modified_by_ref"}
            }
