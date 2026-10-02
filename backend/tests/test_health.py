from __future__ import annotations

import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.core.health import CheckResult, HealthRegistry
from app.main import create_app
from tests.conftest import SettingsFactory


def test_liveness(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "version": __version__,
        "env": "test",
        "dry_run": True,
        "offline_mode": True,
    }


def test_security_headers_and_request_id(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    uuid.UUID(resp.headers["X-Request-ID"])

    supplied = str(uuid.uuid4())
    echoed = client.get("/api/health", headers={"X-Request-ID": supplied})
    assert echoed.headers["X-Request-ID"] == supplied

    forged = client.get("/api/health", headers={"X-Request-ID": "x\r\nSet-Cookie: a=b"})
    assert forged.headers["X-Request-ID"] != "x\r\nSet-Cookie: a=b"
    uuid.UUID(forged.headers["X-Request-ID"])


def test_readiness_reports_unconfigured_dependencies(client: TestClient) -> None:
    resp = client.get("/api/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["config"]["status"] == "ok"
    assert body["checks"]["config"]["detail"] == "enforcement=dry-run"
    for name in ("database", "neo4j", "mqtt"):
        assert body["checks"][name]["status"] == "not_configured"


def test_readiness_flags_enforcing_mode(make_settings: SettingsFactory) -> None:
    settings = make_settings(
        dry_run=False,
        neo4j_uri="bolt://neo4j:7687",
        neo4j_password="pw-123456",
        mqtt_host="broker",
        mqtt_username="u",
        mqtt_password="p",
    )
    with TestClient(create_app(settings)) as c:
        checks = c.get("/api/health/ready").json()["checks"]
    assert checks["config"]["detail"] == "enforcement=ENFORCING"
    assert "Phase 1" in checks["neo4j"]["detail"]
    assert "Phase 4" in checks["mqtt"]["detail"]


def test_readiness_503_when_a_check_errors(client: TestClient) -> None:
    async def broken() -> CheckResult:
        raise ConnectionError("bolt://user:hunter2@neo4j")

    client.app.state.health.register("broken", broken)  # type: ignore[attr-defined]
    resp = client.get("/api/health/ready")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["broken"] == {
        "status": "error",
        "detail": "ConnectionError",
        "latency_ms": body["checks"]["broken"]["latency_ms"],
    }
    assert "hunter2" not in resp.text


def test_cors_allows_only_configured_origin(client: TestClient) -> None:
    preflight = {"Access-Control-Request-Method": "GET"}
    ok = client.options("/api/health", headers={"Origin": "http://localhost:5173", **preflight})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:5173"
    bad = client.options("/api/health", headers={"Origin": "https://evil.example", **preflight})
    assert "access-control-allow-origin" not in bad.headers


def test_openapi_disabled_in_production(make_settings: SettingsFactory) -> None:
    prod = make_settings(env="production", cors_origins=["https://lab.example"])
    with TestClient(create_app(prod)) as c:
        assert c.get("/openapi.json").status_code == 404
        assert c.get("/docs").status_code == 404
        assert c.get("/api/health").status_code == 200


def test_registry_timeout_and_duplicate() -> None:
    registry = HealthRegistry(timeout_s=0.01)

    async def slow() -> CheckResult:
        await asyncio.sleep(1)
        return CheckResult(status="ok")

    registry.register("slow", slow)
    with pytest.raises(ValueError, match="already registered"):
        registry.register("slow", slow)
    results = asyncio.run(registry.run())
    assert results["slow"].status == "error"
    assert results["slow"].detail == "timeout"
