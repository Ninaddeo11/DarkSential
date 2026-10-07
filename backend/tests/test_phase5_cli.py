from __future__ import annotations

from pathlib import Path

import pytest

from app import cli
from tests.conftest import TEST_HMAC_KEY


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("DSN_DEVICE_ID_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.setenv("DSN_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("DSN_MQTT_HOST", raising=False)
    return tmp_path


def test_demo_phase5(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["demo-phase5"]) == 0
    out = capsys.readouterr().out
    lines = {line.split("->")[0].strip(): line.split("->")[1].strip()
             for line in out.splitlines() if "->" in line}  # fmt: skip
    assert lines["valid"] == "accepted"
    for rejected in ("nested topic", "oversized", "rssi out of range", "markup in fw", "not json"):
        assert lines[rejected] == "rejected", rejected
    assert "'mqtt_user': 'esp32-node'" in out
    assert lines["genuine QUARANTINE"] == "ok"
    assert lines["same message replayed"] == "replay"
    assert lines["ALERT altered to RECOVER"] == "bad_sig"
    assert lines["genuine, delivered 2 min late"] == "stale"
    # Only acks for pending commands are audited (the replayed/late ids were consumed).
    assert "audit: mqtt_ack cmd=QUARANTINE  status=ok" in out
    assert "audit: mqtt_ack cmd=ALERT       status=bad_sig" in out
    assert "rule mqtt_wildcard_subscription" in out
    assert "rule mqtt_restricted_publish" in out
    assert "Phase 5 demo OK" in out
