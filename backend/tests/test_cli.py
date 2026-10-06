from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import cli
from tests.conftest import SPACY, TEST_HMAC_KEY


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DSN_DEVICE_ID_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.setenv("DSN_DATABASE_URL", f"sqlite:///{(tmp_path / 'cli.sqlite3').as_posix()}")
    monkeypatch.setenv("DSN_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("DSN_OFFLINE_MODE", "true")


def test_demo_phase1(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["demo-phase1"]) == 0
    out = capsys.readouterr().out
    assert "mitre_attack  mock    success" in out
    assert "Malware:Emotet" in out
    assert "CVE-2023-1389 cvss=" in out
    assert "kev=True" in out
    assert "T1498 Network Denial of Service" in out
    if SPACY:
        assert "Phase 1 demo OK" in out
        assert "CVE-2023-1389" in out.split("== extract")[1]
    else:
        assert "finished WITHOUT NLP" in out


def test_ingest_and_queries(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["ingest", "feodo", "cisa_kev"]) == 0
    assert "feodo         mock    success" in capsys.readouterr().out
    # Each CLI call builds a fresh runtime; without Neo4j the graph is in-memory,
    # so queries in a new process see an empty graph (documented).
    assert cli.main(["related", "162.243.103.246"]) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert cli.main(["cves", "cpe:2.3:o:tp-link:archer_ax21_firmware:1:*:*:*:*:*:*:*"]) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert cli.main(["age"]) == 0
    assert json.loads(capsys.readouterr().out) == {"stale": 0, "purged": 0}


@pytest.mark.skipif(not SPACY, reason="needs spaCy")
def test_extract_command(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["extract", "CVE-2023-1389 at 203.0.113.9"]) == 0
    values = {e["value"] for e in json.loads(capsys.readouterr().out)["entities"]}
    assert values == {"CVE-2023-1389", "203.0.113.9"}
