"""Neo4j-backed GraphStore.

Security: every *value* is passed as a query parameter. Only labels and
relationship types are interpolated, and both come from whitelists
(``ALL_LABELS`` and ``rel_type_for``'s regex); ``_assert_identifier`` re-checks
them right before use.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from typing import Any, LiteralString

from neo4j import Driver, GraphDatabase, NotificationDisabledClassification

from app.graph.cpe import Cpe
from app.graph.project import ALL_LABELS, TERMINAL_LABELS, THREAT_LABELS, GraphBatch
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

_IDENT = re.compile(r"^[A-Z][A-Za-z_]{0,40}$")
_NON_STIX_RELS = ["OBSERVES", "AFFECTS", "DETECTS"]

SCHEMA = [
    "CREATE CONSTRAINT stix_id IF NOT EXISTS FOR (n:StixObject) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT observable_key IF NOT EXISTS FOR (n:Observable) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT cpe_criteria IF NOT EXISTS FOR (n:CPE) REQUIRE n.criteria IS UNIQUE",
    "CREATE CONSTRAINT rule_id IF NOT EXISTS FOR (n:DetectionRule) REQUIRE n.rule_id IS UNIQUE",
    "CREATE INDEX attack_external_id IF NOT EXISTS FOR (n:AttackPattern) ON (n.external_id)",
    "CREATE INDEX cpe_vendor_product IF NOT EXISTS FOR (n:CPE) ON (n.vendor, n.product)",
    "CREATE INDEX indicator_last_seen IF NOT EXISTS FOR (n:Indicator) ON (n.last_seen)",
    "CREATE INDEX stix_name_key IF NOT EXISTS FOR (n:StixObject) ON (n.name_key)",
]

_PROVENANCE = """
    n.last_seen = CASE WHEN n.last_seen IS NULL OR n.last_seen < $seen_at
                       THEN $seen_at ELSE n.last_seen END,
    n.sources = CASE WHEN $source IN n.sources THEN n.sources ELSE n.sources + $source END,
    n.confidence = CASE WHEN n.confidence IS NULL OR n.confidence < row.confidence
                        THEN row.confidence ELSE n.confidence END
"""


def _assert_identifier(value: str) -> str:
    if not _IDENT.fullmatch(value):
        raise ValueError(f"unsafe Cypher identifier: {value!r}")
    return value


def _q(text: str) -> LiteralString:
    # Queries are assembled only from constants and whitelisted identifiers.
    return text


class Neo4jGraphStore:
    def __init__(
        self,
        uri: str,
        user: str,
        password: str,
        database: str | None = None,
        driver: Driver | None = None,
    ) -> None:
        self._driver = driver or GraphDatabase.driver(
            uri,
            auth=(user, password),
            # Expected notices: queries name labels that may not exist yet
            # (UNRECOGNIZED), and IF NOT EXISTS schema statements report "already
            # exists" (SCHEMA). Deprecation/performance/security notices stay on.
            notifications_disabled_classifications=[
                NotificationDisabledClassification.UNRECOGNIZED,
                NotificationDisabledClassification.SCHEMA,
            ],
        )
        self._db = database

    # --- plumbing ---------------------------------------------------------------------

    def _run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        records, _, _ = self._driver.execute_query(_q(query), params, database_=self._db)
        return [record.data() for record in records]

    def ensure_schema(self) -> None:
        for statement in SCHEMA:
            self._run(statement)

    def ping(self) -> None:
        self._driver.verify_connectivity()

    def close(self) -> None:
        self._driver.close()

    def clear(self) -> None:
        """Delete everything (tests only)."""
        self._run("MATCH (n) DETACH DELETE n")

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
        base = {"source": source, "seen_at": seen_at}

        by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for rec in batch.nodes:
            conf = rec.confidence if rec.confidence is not None else confidence
            by_label[rec.label].append({"id": rec.id, "props": rec.props, "confidence": conf})
        for label, rows in by_label.items():
            if label not in ALL_LABELS:
                raise ValueError(f"unknown label {label!r}")
            ttl = ", n.ttl_days = $ttl_days" if label == "Indicator" else ""
            self._run(
                f"""
                UNWIND $rows AS row
                MERGE (n:StixObject {{id: row.id}})
                ON CREATE SET n.first_seen = $seen_at, n.sources = []
                SET n:{_assert_identifier(label)}, n += row.props, n.stale = false,
                {_PROVENANCE}{ttl}
                """,
                rows=rows,
                ttl_days=ttl_days,
                **base,
            )
            stats.nodes += len(rows)

        by_rel: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for edge in batch.edges:
            conf = edge.confidence if edge.confidence is not None else confidence
            by_rel[edge.rel_type].append(
                {"id": edge.id, "src": edge.src, "tgt": edge.tgt, "confidence": conf}
            )
        for rel_type, rows in by_rel.items():
            result = self._run(
                f"""
                UNWIND $rows AS row
                MATCH (a:StixObject {{id: row.src}})
                MATCH (b:StixObject {{id: row.tgt}})
                MERGE (a)-[n:{_assert_identifier(rel_type)} {{id: row.id}}]->(b)
                ON CREATE SET n.sources = []
                SET {_PROVENANCE}
                RETURN count(n) AS created
                """,
                rows=rows,
                **base,
            )
            linked = int(result[0]["created"]) if result else 0
            stats.edges += linked
            stats.skipped_edges += len(rows) - linked

        if batch.observables:
            self._run(
                """
                UNWIND $rows AS row
                MATCH (i:StixObject {id: row.indicator_id})
                MERGE (o:Observable {key: row.key})
                ON CREATE SET o.type = row.type, o.value = row.value
                MERGE (i)-[:OBSERVES]->(o)
                """,
                rows=[vars(o) for o in batch.observables],
            )
            stats.observables = len(batch.observables)

        if batch.cpes:
            self._run(
                """
                UNWIND $rows AS row
                MATCH (v:StixObject {id: row.vulnerability_id})
                MERGE (c:CPE {criteria: row.criteria})
                ON CREATE SET c.part = row.part, c.vendor = row.vendor,
                              c.product = row.product, c.version = row.version
                MERGE (v)-[a:AFFECTS]->(c)
                SET a = row.range
                """,
                rows=[vars(c) for c in batch.cpes],
            )
            stats.cpes = len(batch.cpes)

        technique_rows = [vars(m) for m in batch.mentions if m.technique_id]
        name_rows = [vars(m) for m in batch.mentions if m.name_key]
        if technique_rows:
            res = self._run(
                """
                UNWIND $rows AS row
                MATCH (r:StixObject {id: row.report_id})
                MATCH (t:AttackPattern {external_id: row.technique_id})
                MERGE (r)-[m:MENTIONS {id: row.report_id + '|mentions|' + t.id}]->(t)
                ON CREATE SET m.sources = []
                SET m.sources = CASE WHEN $source IN m.sources
                                     THEN m.sources ELSE m.sources + $source END
                RETURN count(m) AS n
                """,
                rows=technique_rows,
                source=source,
            )
            stats.mentions += int(res[0]["n"]) if res else 0
        if name_rows:
            res = self._run(
                """
                UNWIND $rows AS row
                MATCH (r:StixObject {id: row.report_id})
                MATCH (t:StixObject)
                WHERE (t:Malware OR t:Tool OR t:IntrusionSet OR t:Campaign)
                  AND row.name_key IN t.alias_keys
                MERGE (r)-[m:MENTIONS {id: row.report_id + '|mentions|' + t.id}]->(t)
                ON CREATE SET m.sources = []
                SET m.sources = CASE WHEN $source IN m.sources
                                     THEN m.sources ELSE m.sources + $source END
                RETURN count(m) AS n
                """,
                rows=name_rows,
                source=source,
            )
            stats.mentions += int(res[0]["n"]) if res else 0
        return stats

    def age_indicators(self, now: datetime) -> AgingStats:
        purged = self._run(
            """
            MATCH (i:Indicator)
            WHERE i.ttl_days IS NOT NULL
              AND i.last_seen < $now - duration({days: 2 * i.ttl_days})
            DETACH DELETE i
            RETURN count(*) AS n
            """,
            now=now,
        )
        self._run("MATCH (o:Observable) WHERE NOT (o)<-[:OBSERVES]-() DELETE o")
        stale = self._run(
            """
            MATCH (i:Indicator)
            WHERE i.ttl_days IS NOT NULL AND coalesce(i.stale, false) = false
              AND i.last_seen < $now - duration({days: i.ttl_days})
            SET i.stale = true
            RETURN count(i) AS n
            """,
            now=now,
        )
        return AgingStats(stale=int(stale[0]["n"]), purged=int(purged[0]["n"]))

    def link_rule(self, rule_id: str, technique_ids: Sequence[str], rationale: str) -> list[str]:
        rows = self._run(
            """
            MERGE (r:DetectionRule {rule_id: $rule_id})
            SET r.rationale = $rationale
            WITH r
            OPTIONAL MATCH (r)-[old:DETECTS]->()
            DELETE old
            WITH DISTINCT r
            UNWIND $tids AS tid
            OPTIONAL MATCH (t:AttackPattern {external_id: tid})
            FOREACH (_ IN CASE WHEN t IS NULL THEN [] ELSE [1] END | MERGE (r)-[:DETECTS]->(t))
            RETURN tid, t IS NOT NULL AS found
            """,
            rule_id=rule_id,
            rationale=rationale,
            tids=list(technique_ids),
        )
        return [row["tid"] for row in rows if not row["found"]]

    # --- reads ------------------------------------------------------------------------

    def related_threats(self, ioc: str, max_hops: int = 3) -> list[RelatedThreat]:
        if not 1 <= max_hops <= 5:
            raise ValueError("max_hops must be 1..5")
        results: list[RelatedThreat] = []
        for indicator in self.indicators_for(ioc):
            results.extend(self._related(indicator, max_hops))
        return merge_related(results)

    def related_from_node(self, node_id: str, max_hops: int = 3) -> list[RelatedThreat]:
        if not 1 <= max_hops <= 5:
            raise ValueError("max_hops must be 1..5")
        rows = self._run(
            """
            MATCH (n:StixObject {id: $id})
            RETURN n {.id, .name, .external_id, .confidence, .sources, .stale,
                      label: [l IN labels(n) WHERE l <> 'StixObject'][0]} AS n
            """,
            id=node_id,
        )
        return merge_related(self._related(rows[0]["n"], max_hops)) if rows else []

    def _related(self, start: dict[str, Any], max_hops: int) -> list[RelatedThreat]:
        rows = self._run(
            f"""
            MATCH p = (i:StixObject {{id: $id}})-[rels*1..{int(max_hops)}]-(t:StixObject)
            WHERE all(r IN rels WHERE NOT type(r) IN $non_stix)
              AND all(n IN nodes(p)[1..-1]
                      WHERE none(l IN labels(n) WHERE l IN $terminal))
              AND none(n IN nodes(p) WHERE n:Identity)
            RETURN [n IN nodes(p) | n {{.id, .name, .external_id, .confidence,
                      .sources, .stale,
                      label: [l IN labels(n) WHERE l <> 'StixObject'][0]}}] AS nodes,
                   [r IN relationships(p) | type(r)] AS rels
            """,
            id=start["id"],
            non_stix=_NON_STIX_RELS,
            terminal=sorted(TERMINAL_LABELS),
        )
        paths = [RawPath(tuple(r["nodes"]), tuple(r["rels"])) for r in rows]
        return select_best_paths(start, paths, THREAT_LABELS)

    def indicators_for(self, ioc: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for key in observable_keys_for_ioc(ioc):
            out += [
                r["i"]
                for r in self._run(
                    """
                    MATCH (:Observable {key: $key})<-[:OBSERVES]-(i:Indicator)
                    RETURN i {.id, .name, .external_id, .confidence, .sources, .stale,
                              .pattern, label: 'Indicator'} AS i
                    ORDER BY i.id
                    """,
                    key=key,
                )
            ]
        return out

    def node_by_name(self, label: str, name: str) -> str | None:
        if label not in ALL_LABELS:
            raise ValueError(f"unknown label {label!r}")
        rows = self._run(
            f"MATCH (n:{_assert_identifier(label)} {{name: $name}}) RETURN n.id AS id LIMIT 1",
            name=name,
        )
        return str(rows[0]["id"]) if rows else None

    def cves_for_cpe(self, cpe: str) -> list[CveMatch]:
        target = Cpe.parse(cpe)
        rows = self._run(
            """
            MATCH (v:Vulnerability)-[a:AFFECTS]->(c:CPE {vendor: $vendor, product: $product})
            RETURN v {.id, .cve, .cvss_score, .cvss_severity, .kev, .kev_ransomware,
                      .kev_due_date} AS v,
                   c.criteria AS criteria, properties(a) AS range
            """,
            vendor=target.vendor,
            product=target.product,
        )
        candidates = [
            CpeCandidate(vulnerability=r["v"], criteria=r["criteria"], range=r["range"])
            for r in rows
        ]
        return filter_cpe_candidates(cpe, candidates)

    def techniques_for_behavior(self, rule_id: str) -> list[TechniqueRef]:
        rows = self._run(
            """
            MATCH (:DetectionRule {rule_id: $rule_id})-[:DETECTS]->(t:AttackPattern)
            RETURN t.external_id AS external_id, t.name AS name,
                   coalesce(t.tactics, []) AS tactics, t.id AS stix_id
            ORDER BY external_id
            """,
            rule_id=rule_id,
        )
        return [TechniqueRef(**r) for r in rows]

    def named_entities(self) -> list[tuple[str, str, list[str]]]:
        rows = self._run(
            """
            MATCH (n:StixObject)
            WHERE (n:Malware OR n:Tool OR n:IntrusionSet OR n:Campaign) AND n.name IS NOT NULL
            RETURN n.stix_type AS type, n.name AS name, coalesce(n.aliases, []) AS aliases
            ORDER BY type, name
            """
        )
        return [(r["type"], r["name"], list(r["aliases"])) for r in rows]

    def technique_ids(self) -> set[str]:
        rows = self._run(
            "MATCH (t:AttackPattern) WHERE t.external_id IS NOT NULL "
            "RETURN collect(t.external_id) AS ids"
        )
        return set(rows[0]["ids"]) if rows else set()

    def counts(self) -> dict[str, int]:
        rows = self._run(
            """
            MATCH (n)
            RETURN [l IN labels(n) WHERE l <> 'StixObject'][0] AS label, count(*) AS n
            """
        )
        out = {r["label"]: int(r["n"]) for r in rows if r["label"]}
        rels = self._run(
            "MATCH ()-[r]->() WHERE NOT type(r) IN $non_stix RETURN count(r) AS n",
            non_stix=_NON_STIX_RELS,
        )
        out["relationships"] = int(rels[0]["n"])
        return dict(sorted(out.items()))
