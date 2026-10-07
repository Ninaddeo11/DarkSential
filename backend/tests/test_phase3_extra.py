from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app import cli
from app.behavior.config import load_behavior_config
from app.core.config import Settings
from app.detect.rules import RuleEngine
from app.risk import ablation
from app.risk.config import load_risk_config
from app.risk.dataset import ATTACKS, scenario, windows
from tests.conftest import SKLEARN, TEST_HMAC_KEY


def test_scenario_is_deterministic_and_labelled(settings: Settings) -> None:
    cfg = load_behavior_config(settings.behavior_config_path)
    a, b = scenario(3, minutes=60), scenario(3, minutes=60)
    assert [le.event for le in a.events] == [le.event for le in b.events]
    labels = {le.label for le in a.events}
    assert "normal" in labels
    assert labels - {"normal"} <= set(ATTACKS)
    ws = windows(a, cfg)
    assert any(w.label for w in ws)
    assert any(not w.label for w in ws)
    for w in ws:
        assert w.label == int(bool(w.kinds))
    # Attacks only after the warm-up, so baselines can mature first.
    first_attack = min(le.event.ts for le in a.events if le.label != "normal")
    assert first_attack >= datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=35)


def test_summarize_metrics_math() -> None:
    pytest.importorskip("sklearn.metrics")
    rows = [
        {
            "label": 1,
            "kinds": "mqtt_flood",
            **{m: 1.0 for m in ("rules", "zscore", "iforest", "combined", "pipeline", "xgboost")},
            "linear": 30.0,
        },
        {
            "label": 1,
            "kinds": "port_scan",
            **{m: 0.0 for m in ("rules", "zscore", "iforest", "combined", "pipeline", "xgboost")},
            "linear": 0.0,
        },
        {
            "label": 0,
            "kinds": "",
            **{m: 0.0 for m in ("rules", "zscore", "iforest", "combined", "pipeline", "xgboost")},
            "linear": 0.0,
        },
        {
            "label": 0,
            "kinds": "",
            **{m: 0.7 for m in ("rules", "zscore", "iforest", "combined", "pipeline", "xgboost")},
            "linear": 12.0,
        },
    ]
    summary = {s["method"]: s for s in ablation.summarize(rows)}
    xgb = summary["xgboost"]
    assert (xgb["tp"], xgb["fp"], xgb["fn"], xgb["tn"]) == (1, 1, 1, 1)
    assert (xgb["precision"], xgb["recall"], xgb["fpr"]) == (0.5, 0.5, 0.5)
    assert summary["pipeline"]["tp"] == 1  # threshold 1.0
    assert summary["pipeline"]["fp"] == 0
    per = {r["attack"]: r for r in ablation.recall_by_attack(rows)}
    assert per["mqtt_flood"]["xgboost"] == 1.0
    assert per["port_scan"]["xgboost"] == 0.0


@pytest.mark.skipif(not SKLEARN, reason="needs the ML stack")
def test_ablation_run_small(settings: Settings) -> None:
    pytest.importorskip("shap")
    result = ablation.run(
        load_behavior_config(settings.behavior_config_path),
        load_risk_config(settings.risk_config_path),
        RuleEngine.load(settings.rules_config_path),
        test_seeds=[1],
        train_seeds=[100, 101],
        minutes=60,
    )
    methods = {s["method"] for s in result.summary}
    assert methods == set(ablation.OPERATING_POINTS)
    assert all(0.0 <= s["roc_auc"] <= 1.0 for s in result.summary)
    assert {r["label"] for r in result.windows} == {0, 1}
    assert result.xgb_global_importance


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("DSN_DEVICE_ID_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.setenv("DSN_DATABASE_URL", f"sqlite:///{(tmp_path / 'cli.sqlite3').as_posix()}")
    monkeypatch.setenv("DSN_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("DSN_MODELS_DIR", str(tmp_path / "models"))
    monkeypatch.setenv("DSN_IFOREST_AUTOTRAIN", "false")
    monkeypatch.setenv("DSN_XGB_AUTOTRAIN", "false")
    return tmp_path


def test_demo_phase3(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["demo-phase3"]) == 0
    out = capsys.readouterr().out
    assert "archer-gw      51.0  high     review_quarantine" in out
    assert "protected host: never quarantined" in out
    assert "contacted 162.243.103.246, a known indicator linked to Emotet" in out
    assert "evidence path: Indicator:ipv4-addr 162.243.103.246 -> INDICATES Malware:Emotet" in out
    assert "THREAT_CORRELATED" in out
    assert "Phase 3 demo OK" in out


def test_risk_cli(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from tests.conftest import FIXTURES

    assert cli.main(["discover-xml", str(FIXTURES / "events" / "lab-scan.nmap.xml")]) == 0
    node_id = json.loads(capsys.readouterr().out)[0]
    assert cli.main(["risk", node_id]) == 0
    decision = json.loads(capsys.readouterr().out)
    assert decision["node_id"] == node_id
    assert round(sum(c["contribution"] for c in decision["contributions"]), 2) == decision["score"]
    assert cli.main(["risk", "dev-0000000000000000"]) == 1
