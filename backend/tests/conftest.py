from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.main import create_app

TEST_HMAC_KEY = "test-hmac-key-that-is-definitely-32-bytes-long"

SettingsFactory = Callable[..., Settings]


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Strip any DSN_* variables from the developer's shell so tests are hermetic."""
    for key in list(os.environ):
        if key.startswith("DSN_"):
            monkeypatch.delenv(key)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def make_settings() -> SettingsFactory:
    def _make(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "env": "test",
            "device_id_hmac_key": TEST_HMAC_KEY,
            "log_json": True,
        }
        values.update(overrides)
        return Settings(_env_file=None, **values)

    return _make


@pytest.fixture
def settings(make_settings: SettingsFactory) -> Settings:
    return make_settings()


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client
