from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tests.conftest import TEST_HMAC_KEY, SettingsFactory

ENTRYPOINT = Path(__file__).resolve().parents[2] / "api" / "index.py"


def _load_entrypoint() -> ModuleType:
    spec = importlib.util.spec_from_file_location("vercel_index", ENTRYPOINT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def vercel_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.setenv("DSN_DEVICE_ID_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.setenv("VERCEL_PROJECT_PRODUCTION_URL", "dsn.vercel.app")
    monkeypatch.delenv("DSN_DEPLOYMENT", raising=False)
    monkeypatch.setattr(sys, "path", list(sys.path))
    return monkeypatch


def test_hosted_requires_dry_run(make_settings: SettingsFactory) -> None:
    with pytest.raises(ValidationError, match="dry-run only"):
        make_settings(deployment="hosted", dry_run=False)
    assert make_settings(deployment="hosted").dry_run is True


def test_entrypoint_forces_hosted_production(vercel_env: pytest.MonkeyPatch) -> None:
    vercel_env.setenv("DSN_DEPLOYMENT", "lab")  # must be overridden, not respected
    module = _load_entrypoint()
    with TestClient(module.app) as client:
        body = client.get("/api/health").json()
        assert body["deployment"] == "hosted"
        assert body["env"] == "production"
        assert body["dry_run"] is True
        assert client.get("/openapi.json").status_code == 404
        preflight = client.options(
            "/api/health",
            headers={"Origin": "https://dsn.vercel.app", "Access-Control-Request-Method": "GET"},
        )
        assert preflight.headers["access-control-allow-origin"] == "https://dsn.vercel.app"


def test_entrypoint_refuses_enforcement(vercel_env: pytest.MonkeyPatch) -> None:
    vercel_env.setenv("DSN_DRY_RUN", "false")
    with pytest.raises(ValidationError, match="dry-run only"):
        _load_entrypoint()
