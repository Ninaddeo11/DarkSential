"""GraphStore contract: identical behavior for the in-memory and Neo4j stores.

Neo4j runs when DSN_TEST_NEO4J_URI (and _USER/_PASSWORD) is set, e.g. in CI's
service container or `python scripts/tasks.py docker-test`; otherwise skipped.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.feeds.config import load_feeds_config
from app.feeds.registry import build_adapter
from app.graph.memory import InMemoryGraphStore
from app.graph.project import EdgeRecord, GraphBatch, project, rel_type_for
from app.graph.store import (
    HOP_DECAY,
    GraphStore,
    RawPath,
    RelatedThreat,
    _path_confidence,
    merge_related,
    observable_keys_for_ioc,
)
from app.intel.nlp import EntityExtractor, Gazetteer, GazetteerEntry
from app.intel.stix import stix_id
from tests.conftest import SPACY

T0 = datetime(2026, 10, 1, tzinfo=UTC)
# Read at import: the autouse _isolated_env fixture strips DSN_* before tests run.
NEO4J_URI = os.environ.get("DSN_TEST_NEO4J_URI")
NEO4J_USER = os.environ.get("DSN_TEST_NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("DSN_TEST_NEO4J_PASSWORD", "")

STORES = ["memory", pytest.param("neo4j", marks=pytest.mark.neo4j)]


@pytest.fixture(params=STORES)
def store(request: pytest.FixtureRequest) -> Iterator[GraphStore]:
    if request.param == "memory":
        yield InMemoryGraphStore()
        return
    if not NEO4J_URI:
        pytest.skip("DSN_TEST_NEO4J_URI not set")
    from app.graph.neo4j_store import Neo4jGraphStore

    neo = Neo4jGraphStore(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    try:
        neo.clear()
        neo.ensure_schema()
        yield neo
        neo.clear()
    finally:
        neo.close()


def ingest(store: GraphStore, settings: Settings, names: list[str], at: datetime = T0) -> None:
    feeds = load_feeds_config(settings.feeds_config_path).feeds

    def extractor() -> EntityExtractor:
        return EntityExtractor(
            Gazetteer(
                [GazetteerEntry(k, n, tuple(a)) for k, n, a in store.named_entities()],
                frozenset(store.technique_ids()),
            )
        )

    for name in names:
        adapter = build_adapter(settings, feeds[name], extractor, clock=lambda: at)
        objects = adapter.normalize_to_stix(adapter.fetch()).objects
        cfg = feeds[name]
        store.upsert(
            project(objects),
            source=name,
            confidence=cfg.confidence,
            ttl_days=cfg.ttl_days,
            seen_at=at,
        )


BASE_FEEDS = ["mitre_attack", "cisa_kev", "nvd_cve", "feodo", "threatfox", "urlhaus"]


def test_related_threats_feodo_ip(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, BASE_FEEDS)
    threats = store.related_threats("162.243.103[.]246")
    by_name = {t.name: t for t in threats}
    emotet = by_name["Emotet"]
    assert emotet.hops == 1
    assert emotet.label == "Malware"
    assert [s.via for s in emotet.path] == [None, "INDICATES"]
    # Feodo's "Emotet" is its own Malware node (deterministic DSN id), distinct
    # from ATT&CK's Emotet (MITRE id); they are not merged by name. Limitation
    # documented in docs/architecture.md.
    assert emotet.sources == ["feodo"]
    assert emotet.indicator_stale is False
    assert 0 < emotet.confidence <= 1


def test_related_threats_qakbot_via_threatfox(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, BASE_FEEDS)
    threats = {t.name for t in store.related_threats("203.0.113.10")}
    assert "QakBot" in threats


def test_related_threats_unknown_and_hostile_inputs(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, ["feodo"])
    assert store.related_threats("198.18.0.1") == []
    assert store.related_threats("x' OR 1=1 //") == []
    assert store.related_threats("'}) MATCH (n) DETACH DELETE n //") == []
    assert store.counts().get("Indicator") == 5  # nothing was deleted


@pytest.mark.skipif(not SPACY, reason="dark-web ingestion needs spaCy")
def test_darkweb_report_links_attack_and_names(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, [*BASE_FEEDS, "darkweb"])
    threats = store.related_threats("192.0.2.45")
    labels = {(t.label, t.name) for t in threats}
    # Indicator <- Report -> mentioned technique / CVE / co-mentioned indicator
    assert ("Report", "Dark-web mention dw-0001 (forum-alpha)") in labels
    assert any(
        lbl == "AttackPattern" and name == "Exploit Public-Facing Application"
        for lbl, name in labels
    )
    assert ("Vulnerability", None) not in labels
    vuln = next(t for t in threats if t.label == "Vulnerability")
    assert vuln.hops == 2
    assert [s.via for s in vuln.path] == [None, "REFERS_TO", "REFERS_TO"]
    # Two indicators observe this IP (Feodo ip:port + dark-web mention) and both
    # abuse.ch and ATT&CK name Emotet/QakBot: results are still one per threat.
    emotet_ip = store.related_threats("162.243.103.246")
    keys = [(t.label, (t.name or "").casefold()) for t in emotet_ip]
    assert len(keys) == len(set(keys))
    by_name = {t.name: t for t in emotet_ip}
    assert by_name["Emotet"].hops == 1  # the direct Feodo link wins over report paths
    assert {"QakBot", "Sandworm Team"} <= set(by_name)  # via the dark-web report's names
    # Farther = weaker: every 3-hop result scores below the direct link.
    assert all(t.confidence < by_name["Emotet"].confidence for t in emotet_ip if t.hops == 3)


def test_paths_do_not_traverse_through_techniques(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, ["mitre_attack"])
    # Seed an indicator for QakBot (ATT&CK id) and check other malware sharing
    # techniques is NOT reported via the technique hub.
    from app.intel.stix import build_indicator, build_relationship, make_observable, validate

    attack_qakbot_id = _id_by_name(store, "QakBot")
    ind = build_indicator(
        make_observable("ipv4-addr", "203.0.113.77"), source="t", confidence=90, valid_from=T0
    )
    rel = build_relationship(ind.id, "indicates", attack_qakbot_id, confidence=90, source="t")
    store.upsert(
        project([validate(ind), validate(rel)]), source="t", confidence=90, ttl_days=30, seen_at=T0
    )
    threats = store.related_threats("203.0.113.77")
    labels = {t.label for t in threats}
    assert "AttackPattern" in labels  # QakBot -> uses -> technique (terminal)
    malware = {t.name for t in threats if t.label == "Malware"}
    assert malware == {"QakBot"}  # no Emotet via shared "Web Protocols" technique
    assert all(t.hops <= 3 for t in threats)


def _id_by_name(store: GraphStore, name: str) -> str:
    if isinstance(store, InMemoryGraphStore):
        return next(n.id for n in store._nodes.values() if n.props.get("name") == name)
    rows = store._run("MATCH (n:StixObject {name: $name}) RETURN n.id AS id LIMIT 1", name=name)  # type: ignore[attr-defined]
    return str(rows[0]["id"])


def test_cves_for_cpe(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, ["cisa_kev", "nvd_cve"])
    matches = store.cves_for_cpe("cpe:2.3:o:tp-link:archer_ax21_firmware:1.1.1:*:*:*:*:*:*:*")
    assert [m.cve for m in matches] == ["CVE-2023-1389"]
    m = matches[0]
    assert m.kev
    assert m.match == "range"
    assert m.cvss_score
    patched = store.cves_for_cpe("cpe:2.3:o:tp-link:archer_ax21_firmware:99.0:*:*:*:*:*:*:*")
    assert patched == []
    huawei = store.cves_for_cpe("cpe:2.3:o:huawei:hg532_firmware:*:*:*:*:*:*:*:*")
    assert [(h.cve, h.kev, h.match) for h in huawei] == [("CVE-2017-17215", False, "any-version")]
    with pytest.raises(ValueError, match="CPE"):
        store.cves_for_cpe("not-a-cpe")


def test_kev_and_nvd_merge_with_provenance(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, ["cisa_kev"], at=T0)
    ingest(store, settings, ["nvd_cve"], at=T0 + timedelta(hours=1))
    matches = store.cves_for_cpe("cpe:2.3:o:tp-link:archer_ax21_firmware:1.0:*:*:*:*:*:*:*")
    assert matches[0].kev  # KEV flag survived NVD upsert (no null overwrite)
    if isinstance(store, InMemoryGraphStore):
        node = store.node(stix_id("vulnerability", "CVE-2023-1389"))
        assert node is not None
        assert sorted(node["sources"]) == ["cisa_kev", "nvd_cve"]
        assert node["first_seen"] == T0
        assert node["last_seen"] == T0 + timedelta(hours=1)
        assert node["confidence"] == 95  # max of KEV 95 / NVD 85


def test_aging_marks_stale_then_purges(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, ["feodo"], at=T0)  # ttl 14 days
    assert store.age_indicators(T0 + timedelta(days=10)).model_dump() == {"stale": 0, "purged": 0}
    assert store.age_indicators(T0 + timedelta(days=15)).stale == 5
    assert store.related_threats("50.16.16.211")[0].indicator_stale is True
    # Re-seen -> fresh again.
    ingest(store, settings, ["feodo"], at=T0 + timedelta(days=16))
    assert store.related_threats("50.16.16.211")[0].indicator_stale is False
    purge = store.age_indicators(T0 + timedelta(days=16 + 29))
    assert purge.purged == 5
    assert store.related_threats("50.16.16.211") == []
    assert store.counts().get("Malware", 0) >= 1  # malware nodes don't age out


def test_vulnerabilities_and_attack_never_age(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, ["cisa_kev", "mitre_attack"], at=T0)
    before = store.counts()
    store.age_indicators(T0 + timedelta(days=3650))
    assert store.counts() == before


def test_rule_technique_mapping(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, ["mitre_attack"])
    missing = store.link_rule("mqtt_connect_flood", ["T1498", "T1499", "T9999"], "DoS")
    assert missing == ["T9999"]
    techniques = store.techniques_for_behavior("mqtt_connect_flood")
    assert [t.external_id for t in techniques] == ["T1498", "T1499"]
    assert "impact" in techniques[0].tactics
    # Re-linking replaces the mapping.
    store.link_rule("mqtt_connect_flood", ["T1499"], "endpoint only")
    assert [t.external_id for t in store.techniques_for_behavior("mqtt_connect_flood")] == ["T1499"]
    assert store.techniques_for_behavior("unknown_rule") == []


def test_named_entities_and_technique_ids(store: GraphStore, settings: Settings) -> None:
    ingest(store, settings, ["mitre_attack"])
    names = {name: (kind, aliases) for kind, name, aliases in store.named_entities()}
    assert names["Sandworm Team"][0] == "intrusion-set"
    assert "Voodoo Bear" in names["Sandworm Team"][1]
    assert names["QakBot"][0] == "malware"
    assert {"T1190", "T1110.001", "T0814"} <= store.technique_ids()


def test_counts_and_skipped_edges(store: GraphStore, settings: Settings) -> None:
    batch = GraphBatch(
        edges=[EdgeRecord("relationship--x", "malware--missing", "malware--gone", "USES", 50)]
    )
    stats = store.upsert(batch, source="t", confidence=50, ttl_days=None, seen_at=T0)
    assert stats.skipped_edges == 1
    assert stats.edges == 0
    ingest(store, settings, ["feodo"])
    counts = store.counts()
    assert counts["Indicator"] == 5
    assert counts["Observable"] == 5
    assert counts["relationships"] >= 5


# --- pure helpers ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("ioc", "key"),
    [
        ("162.243.103[.]246", "ipv4-addr:162.243.103.246"),
        ("2001:DB8::1", "ipv6-addr:2001:db8::1"),
        ("Evil.Example.COM.", "domain-name:evil.example.com"),
        ("hxxp://x.test/a", "url:http://x.test/a"),
        ("5D41402ABC4B2A76B9719D911017C592", "file-md5:5d41402abc4b2a76b9719d911017c592"),
    ],
)
def test_observable_keys_for_ioc(ioc: str, key: str) -> None:
    assert observable_keys_for_ioc(ioc) == [key]


def test_observable_keys_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        observable_keys_for_ioc("  ")


def _threat(tid: str, name: str, hops: int, conf: float, label: str = "Malware") -> RelatedThreat:
    return RelatedThreat(
        threat_id=tid,
        label=label,
        name=name,
        external_id=None,
        hops=hops,
        confidence=conf,
        sources=[],
        indicator_id="indicator--1",
        indicator_stale=False,
        path=[],
    )


def test_merge_related_dedupes_by_label_and_name() -> None:
    merged = merge_related(
        [
            _threat("malware--a", "QakBot", 3, 0.9),
            _threat("malware--b", "qakbot", 1, 0.5),
            _threat("malware--c", "QakBot", 1, 0.7),
            _threat("attack-pattern--d", "QakBot", 2, 0.9, label="AttackPattern"),
        ]
    )
    assert [(t.threat_id, t.hops) for t in merged] == [
        ("malware--c", 1),
        ("attack-pattern--d", 2),
    ]


def test_path_confidence_decays_per_hop() -> None:
    nodes = tuple({"id": f"n{i}", "label": "Malware", "confidence": 80} for i in range(4))
    one = RawPath(nodes[:2], ("INDICATES",))
    three = RawPath(nodes, ("INDICATES", "USES", "USES"))
    assert _path_confidence(one) == 0.8
    assert _path_confidence(three) == round(0.8 * HOP_DECAY**2, 3)
    assert _path_confidence(RawPath(({"id": "x", "label": "L"},) * 2, ("R",))) == 0.0


def test_rel_type_whitelist() -> None:
    assert rel_type_for("attributed-to") == "ATTRIBUTED_TO"
    assert rel_type_for("uses]->(x) DETACH DELETE x //") == "RELATED_TO"
    assert rel_type_for("UPPER") == "RELATED_TO"
