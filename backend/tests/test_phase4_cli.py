from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import cli
from tests.conftest import TEST_HMAC_KEY


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("DSN_DEVICE_ID_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.setenv("DSN_DATABASE_URL", f"sqlite:///{(tmp_path / 'cli.sqlite3').as_posix()}")
    monkeypatch.setenv("DSN_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("DSN_MODELS_DIR", str(tmp_path / "models"))
    monkeypatch.setenv("DSN_IFOREST_AUTOTRAIN", "false")
    monkeypatch.setenv("DSN_XGB_AUTOTRAIN", "false")
    return tmp_path


def test_demo_phase4(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["demo-phase4"]) == 0
    out = capsys.readouterr().out
    assert "refused: protected host" in out
    assert "by system:risk-engine" in out
    assert "[dry-run] nft add element inet dsn quarantine_v4 { 192.168.50.24 }" in out
    assert "added back: ['192.168.50.24']; in sync: True" in out
    assert "released 1 quarantine(s); firewall now: []" in out
    assert "HMAC-signed): QUARANTINE, RECOVER" in out
    assert "chain verified: ok=True" in out
    assert "Phase 4 demo OK" in out


def test_quarantine_release_audit_commands(
    cli_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.conftest import FIXTURES

    assert cli.main(["discover-xml", str(FIXTURES / "events" / "lab-scan.nmap.xml")]) == 0
    node_ids = json.loads(capsys.readouterr().out)
    esp = node_ids[-1]
    assert cli.main(["quarantine", esp, "5"]) == 0
    q = json.loads(capsys.readouterr().out)
    assert q["status"] == "active"
    assert q["dry_run"] is True
    assert cli.main(["release", esp]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "released"
    assert cli.main(["audit"]) == 0
    entries = json.loads(capsys.readouterr().out)
    assert {e["action"] for e in entries} >= {"quarantine", "release", "reconcile"}
    assert cli.main(["audit", "--verify"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
