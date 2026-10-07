from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.behavior.features import FEATURES
from app.core.config import Settings
from app.detect.rules import Rule, RuleEngine, RulesFile, evaluate

ZERO = {f: 0.0 for f in FEATURES}


def rule(**kw: object) -> Rule:
    base: dict[str, object] = {
        "id": "test_rule",
        "title": "t",
        "severity": "low",
        "techniques": ["T1046"],
        "rationale": "a sufficiently long justification",
        "when": {"feature": "unique_dst_ports", "op": ">=", "value": 25},
    }
    base.update(kw)
    return Rule.model_validate(base)


def test_shipped_rules_load_and_reference_valid_features(settings: Settings) -> None:
    engine = RuleEngine.load(settings.rules_config_path)
    ids = {r.id for r in engine.rules}
    assert {
        "mqtt_connect_flood",
        "mqtt_wildcard_subscription",
        "mqtt_restricted_publish",
        "credential_brute_force",
        "network_scan",
        "protocol_drift",
        "wifi_deauth_flood",
    } <= ids
    for r in engine.rules:
        assert len(r.rationale) > 40  # every mapping is justified


@pytest.mark.parametrize(
    ("vector", "z", "expected"),
    [
        ({"mqtt_connect_rate": 500}, {}, {"mqtt_connect_flood"}),
        ({"mqtt_connect_rate": 40}, {"mqtt_connect_rate": 9.0}, {"mqtt_connect_flood"}),
        ({"mqtt_connect_rate": 40}, {}, set()),  # z-branch needs a baseline
        ({"mqtt_wildcard_subs": 1}, {}, {"mqtt_wildcard_subscription"}),
        ({"mqtt_restricted_publishes": 2}, {}, {"mqtt_restricted_publish"}),
        ({"failed_attempts": 12}, {}, {"credential_brute_force"}),
        ({"unique_dst_ports": 30}, {}, {"network_scan"}),
        ({"unique_destinations": 60}, {}, {"network_scan"}),
        ({"new_protocols": 1}, {"request_rate": 3.0}, {"protocol_drift"}),
        ({"new_protocols": 1}, {"request_rate": 0.5}, set()),
        ({}, {}, set()),
    ],
)
def test_shipped_rules_fire_as_designed(
    settings: Settings, vector: dict[str, float], z: dict[str, float], expected: set[str]
) -> None:
    hits = RuleEngine.load(settings.rules_config_path).evaluate({**ZERO, **vector}, z)
    assert {h.rule_id for h in hits} == expected
    for h in hits:
        assert h.evidence
        assert h.techniques


def test_evidence_records_matching_comparisons() -> None:
    r = rule(
        when={
            "all": [
                {"feature": "failed_attempts", "op": ">", "value": 3},
                {"z": "request_rate", "op": ">=", "value": 2},
            ]
        }
    )
    ok, ev = evaluate(r.when, {**ZERO, "failed_attempts": 5}, {"request_rate": 2.5})  # type: ignore[arg-type]
    assert ok
    assert [(e.kind, e.name, e.observed, e.threshold) for e in ev] == [
        ("feature", "failed_attempts", 5.0, 3.0),
        ("z", "request_rate", 2.5, 2.0),
    ]


def test_not_and_operators() -> None:
    r = rule(when={"not": {"feature": "dns_rate", "op": "==", "value": 0}})
    assert evaluate(r.when, {**ZERO, "dns_rate": 1}, {})[0]  # type: ignore[arg-type]
    assert not evaluate(r.when, ZERO, {})[0]  # type: ignore[arg-type]
    for op, value, expected in [("<", 1, True), ("<=", 0, True), ("!=", 0, False)]:
        r2 = rule(when={"feature": "dns_rate", "op": op, "value": value})
        assert evaluate(r2.when, ZERO, {})[0] is expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"when": {"feature": "nope", "op": ">", "value": 1}}, "unknown feature"),
        ({"when": {"z": "nope", "op": ">", "value": 1}}, "unknown feature"),
        ({"when": {"feature": "dns_rate", "op": "=~", "value": 1}}, "op"),
        ({"when": {"feature": "dns_rate", "op": ">", "value": "__import__('os')"}}, "value"),
        ({"techniques": ["T12"]}, "invalid technique"),
        ({"id": "Bad Id!"}, "id"),
        ({"rationale": "short"}, "rationale"),
        ({"when": None}, "need a `when`"),
        ({"when": {"all": []}}, "all"),
        ({"when": {"feature": "dns_rate", "op": ">", "value": 1, "extra": 1}}, "extra"),
    ],
)
def test_rule_validation_rejects(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        rule(**overrides)


def test_duplicate_ids_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate"):
        RulesFile(rules=[rule(), rule()])


def test_wifi_rules_skip_traffic_evaluation(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(
        "rules:\n  - id: wifi_only\n    title: w\n    severity: high\n"
        "    techniques: [T1498]\n    rationale: a sufficiently long justification\n"
        "    source: wifi\n",
        encoding="utf-8",
    )
    engine = RuleEngine.load(path)
    assert engine.evaluate({**ZERO, "mqtt_connect_rate": 1e6}, {}) == []
    assert engine.by_id["wifi_only"].source == "wifi"
