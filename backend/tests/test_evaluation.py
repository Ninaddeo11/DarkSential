from __future__ import annotations

from pathlib import Path

import pytest

from app.evaluation import harness
from app.evaluation.harness import ContactRow, DeviceRow, Results, calibrate, summarize
from app.evaluation.report import parse_seeds

pytest.importorskip("sklearn")  # the harness trains the Isolation Forest


def dev(scenario: str, truth: str, score: float, **kw: object) -> DeviceRow:
    level = "critical" if score >= 75 else "medium" if score >= 25 else "low"
    base: dict[str, object] = {
        "scenario": scenario, "seed": 1, "device": f"{scenario}-{truth}-{score}", "truth": truth,
        "max_score": score, "max_level": level, "final_score": score, "final_level": level,
        "alerted": score >= 25, "quarantine_worthy": score >= 75, "quarantined": False,
        "flagged_unknown": truth == "unknown",
    }  # fmt: skip
    base.update(kw)
    return DeviceRow(**base)  # type: ignore[arg-type]


def test_parse_seeds() -> None:
    assert parse_seeds("1-3,7,9-10") == [1, 2, 3, 7, 9, 10]


def test_calibration_rule() -> None:
    r = Results(
        devices=[
            dev("normal", "benign", 0.0),
            dev("unknown_device", "unknown", 10.0),
            dev("mqtt_flood", "malicious", 16.0),
            dev("kev_only", "vulnerable", 34.0),
            dev("kev_ioc", "malicious", 44.0),
            dev("quarantine_recovery", "malicious", 36.0),
        ],
        thresholds={"low": 0, "medium": 25, "high": 50, "critical": 75},
    )
    c = calibrate(r)
    assert c["separable"] is True
    # alert: 10 (must not alert) .. 16 (must alert); critical: 16 (flood alone) .. 36
    # (weakest corroborated compromise). The vulnerable-only device (34) is handled by
    # the engine's compromise-evidence gate, not by this threshold.
    assert c["suggested"] == {"low": 0.0, "medium": 13.0, "high": 19.5, "critical": 26.0}
    assert c["margins"] == {"alert": 6.0, "quarantine": 20.0}


def test_calibration_refuses_overlap() -> None:
    r = Results(
        devices=[
            dev("normal", "benign", 20.0),
            dev("mqtt_flood", "malicious", 16.0),
            dev("kev_only", "vulnerable", 30.0),
            dev("quarantine_recovery", "malicious", 14.0),  # below the flood: overlap
            dev("kev_ioc", "malicious", 40.0),
        ]
    )
    c = calibrate(r)
    assert c["separable"] is False
    assert "suggested" not in c


def test_summary_metrics() -> None:
    r = Results(
        devices=[
            dev("normal", "benign", 0.0),
            dev("normal", "benign", 30.0),  # a false alert
            dev("unknown_device", "unknown", 10.0),
            dev("mqtt_flood", "malicious", 16.0, alerted=True),  # alerts under some thresholds
            dev("kev_ioc", "malicious", 80.0),
        ],
        contacts=[
            ContactRow(1, "a", "162.243.103.246", True, True),
            ContactRow(1, "b", "198.51.100.7", False, False),
            ContactRow(1, "c", "198.51.100.8", False, True),  # a false correlation
        ],
    )
    s = summarize(r)
    assert s["alert_fpr"] == 0.5
    assert s["alert_tpr"] == 1.0
    assert s["quarantine_tpr"] == 1.0  # the multi-signal compromise reached critical
    assert s["single_signal_quarantined"] == 0.0
    assert s["unknown_flagged"] == 1.0
    assert s["correlation"] == {
        "tp": 1, "fn": 0, "fp": 1, "tn": 1, "accuracy": 2 / 3, "precision": 0.5, "recall": 1.0,
    }  # fmt: skip


@pytest.fixture(scope="module")
def one_seed(tmp_path_factory: pytest.TempPathFactory) -> Results:
    models = Path(tmp_path_factory.mktemp("models"))
    results = Results()
    for name in harness.SCENARIOS:
        results.extend(harness.run_scenario(name, 1, models))
    return results


def test_scenarios_produce_expected_ground_truth(one_seed: Results) -> None:
    by = {(d.scenario, d.truth) for d in one_seed.devices}
    assert ("unknown_device", "unknown") in by
    assert {("mqtt_flood", "malicious"), ("kev_ioc", "malicious")} <= by
    assert ("quarantine_recovery", "malicious") in by
    vulnerable = next(d for d in one_seed.devices if d.truth == "vulnerable")
    assert vulnerable.alerted  # KEV exposure is worth an alert under the shipped thresholds
    benign = [d for d in one_seed.devices if d.truth == "benign"]
    assert benign
    assert all(d.max_score == 0 for d in benign)  # approved fleet, normal traffic
    rogue = next(d for d in one_seed.devices if d.truth == "unknown")
    assert rogue.flagged_unknown
    assert not rogue.quarantined
    flood = next(
        d for d in one_seed.devices if d.scenario == "mqtt_flood" and d.truth == "malicious"
    )
    assert flood.first_detection_s is not None
    assert 0 <= flood.first_detection_s <= 120  # within two 60 s windows of the attack
    kev = next(d for d in one_seed.devices if d.scenario == "kev_ioc" and d.truth == "malicious")
    assert kev.correlation_s is not None
    assert all(c.correlated == c.is_indicator for c in one_seed.contacts)
    metrics = {t.metric for t in one_seed.timings}
    assert {"risk_assess_ms", "quarantine_ms", "recovery_s", "discovery_s"} <= metrics
    recovery = [t.value for t in one_seed.timings if t.metric == "recovery_s"]
    assert all(0 <= v <= 60 for v in recovery)  # the 60 s sweep


def test_ws_latency_delivers_everything() -> None:
    pytest.importorskip("socketio")
    pytest.importorskip("websocket")
    from app.evaluation.ws_latency import measure

    samples = measure(steady=20, rate_per_s=100, burst=200)
    assert len(samples) == 220  # measure() raises if any event is lost
    assert all(s.latency_ms >= 0 for s in samples)
