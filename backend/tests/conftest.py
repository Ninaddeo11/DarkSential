from __future__ import annotations

import importlib.util
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from hypothesis import settings as hypothesis_settings

from app.core.config import REPO_ROOT, Settings, get_settings
from app.main import create_app

# Property tests check correctness, not speed: per-example deadlines only add
# flakiness on slower CI runners (e.g. spaCy's first call loading its pipeline).
hypothesis_settings.register_profile("dsn", deadline=None, print_blob=True)
hypothesis_settings.load_profile("dsn")

TEST_HMAC_KEY = "test-hmac-key-that-is-definitely-32-bytes-long"
FIXTURES = REPO_ROOT / "fixtures"

SettingsFactory = Callable[..., Settings]


def _spacy_loads() -> bool:
    # spaCy ships compiled extensions; some hosts (e.g. Windows Smart App Control)
    # block them. Tests that need it skip there and run in CI / Docker.
    if importlib.util.find_spec("spacy") is None:
        return False
    try:
        import spacy

        spacy.blank("en")
    except ImportError:
        return False
    return True


SPACY = _spacy_loads()
requires_spacy = pytest.mark.skipif(not SPACY, reason="spaCy cannot load on this host")


def _sklearn_loads() -> bool:
    try:
        from sklearn.ensemble import IsolationForest  # noqa: F401
    except ImportError:
        return False
    return True


SKLEARN = _sklearn_loads()
requires_sklearn = pytest.mark.skipif(not SKLEARN, reason="scikit-learn cannot load here")


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
def make_settings(tmp_path: Path) -> SettingsFactory:
    def _make(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "env": "test",
            "device_id_hmac_key": TEST_HMAC_KEY,
            "log_json": True,
            "database_url": f"sqlite:///{(tmp_path / 'dsn.sqlite3').as_posix()}",
            "cache_dir": tmp_path / "cache",
            "scheduler_enabled": False,
            "offline_mode": True,
            "models_dir": tmp_path / "models",
            "iforest_autotrain": False,
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
