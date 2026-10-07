from __future__ import annotations

from typing import Any

import pytest

from app import __main__ as entrypoint
from tests.conftest import TEST_HMAC_KEY


def test_main_runs_uvicorn_with_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DSN_DEVICE_ID_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.setenv("DSN_API_HOST", "0.0.0.0")
    monkeypatch.setenv("DSN_API_PORT", "9001")
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr("app.__main__.uvicorn.run", lambda *a, **kw: calls.append((a, kw)))

    entrypoint.main()

    ((args, kwargs),) = calls
    assert args == ("app.main:create_app",)
    assert kwargs["factory"] is True
    assert (kwargs["host"], kwargs["port"]) == ("0.0.0.0", 9001)
    assert kwargs["server_header"] is False
