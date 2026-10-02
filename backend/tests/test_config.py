from __future__ import annotations

import ipaddress

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from tests.conftest import TEST_HMAC_KEY, SettingsFactory


def test_safe_defaults(settings: Settings) -> None:
    assert settings.dry_run is True
    assert settings.offline_mode is True
    assert settings.api_host == "127.0.0.1"
    assert settings.cors_origins == ["http://localhost:5173"]


def test_hmac_key_is_required() -> None:
    with pytest.raises(ValidationError, match="device_id_hmac_key"):
        Settings(_env_file=None)


def test_hmac_key_too_short(make_settings: SettingsFactory) -> None:
    with pytest.raises(ValidationError, match="at least 32 bytes"):
        make_settings(device_id_hmac_key="short")


def test_secrets_not_in_repr(settings: Settings) -> None:
    assert TEST_HMAC_KEY not in repr(settings)
    assert TEST_HMAC_KEY not in str(settings.model_dump())


def test_env_vars_and_csv_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DSN_DEVICE_ID_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.setenv("DSN_DRY_RUN", "false")
    monkeypatch.setenv("DSN_CORS_ORIGINS", "http://localhost:5173, https://lab.example/")
    monkeypatch.setenv("DSN_PROTECTED_HOSTS", "192.168.50.1,192.168.50.2")
    monkeypatch.setenv("DSN_NEO4J_URI", "")  # empty means unset
    s = get_settings()
    assert s.dry_run is False
    assert s.cors_origins == ["http://localhost:5173", "https://lab.example"]
    assert s.is_protected(ipaddress.ip_address("192.168.50.2"))
    assert not s.is_protected(ipaddress.ip_address("192.168.50.3"))
    assert s.neo4j_uri is None
    assert get_settings() is s  # cached


@pytest.mark.parametrize(
    "origin",
    ["*", "http://*.example.com", "ftp://host", "localhost:5173", "http://host/path"],
)
def test_cors_rejects_non_explicit(make_settings: SettingsFactory, origin: str) -> None:
    with pytest.raises(ValidationError, match="CORS origin"):
        make_settings(cors_origins=[origin])


def test_production_requires_https_cors(make_settings: SettingsFactory) -> None:
    with pytest.raises(ValidationError, match="must be https"):
        make_settings(env="production", cors_origins=["http://lab.example"])
    ok = make_settings(env="production", cors_origins=["https://lab.example"])
    assert ok.env == "production"


@pytest.mark.parametrize("cidr", ["8.8.8.0/24", "127.0.0.0/8", "0.0.0.0/0"])
def test_lab_cidr_must_be_private(make_settings: SettingsFactory, cidr: str) -> None:
    with pytest.raises(ValidationError, match="lab_cidr"):
        make_settings(lab_cidr=cidr)


def test_lab_cidr_accepts_private_v4_and_v6(make_settings: SettingsFactory) -> None:
    assert str(make_settings(lab_cidr="10.10.0.0/16").lab_cidr) == "10.10.0.0/16"
    assert str(make_settings(lab_cidr="fd00:1::/64").lab_cidr) == "fd00:1::/64"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"neo4j_uri": "bolt://neo4j:7687"}, "neo4j_password"),
        ({"mqtt_host": "broker", "mqtt_username": "u"}, "mqtt_username and mqtt_password"),
        ({"darkweb_api_url": "https://intel.example/api"}, "darkweb_api_key"),
    ],
)
def test_paired_credentials(
    make_settings: SettingsFactory, overrides: dict[str, str], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        make_settings(**overrides)


def test_darkweb_url_must_be_https(make_settings: SettingsFactory) -> None:
    with pytest.raises(ValidationError, match="https"):
        make_settings(darkweb_api_url="http://intel.example", darkweb_api_key="k" * 10)


def test_secret_values_collects_all_secrets(make_settings: SettingsFactory) -> None:
    s = make_settings(
        neo4j_uri="bolt://neo4j:7687", neo4j_password="neo-pass", nvd_api_key="nvd-key"
    )
    assert set(s.secret_values()) == {TEST_HMAC_KEY, "neo-pass", "nvd-key"}
