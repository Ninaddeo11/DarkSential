"""Typed application settings, loaded from environment / .env.

Every setting is prefixed ``DSN_``. Secrets are ``SecretStr`` so they never
appear in reprs or logs. Validation is strict: the app refuses to start with a
missing HMAC key, a wildcard CORS origin, or a non-private lab CIDR.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# BACKEND_ROOT is the directory holding the `app` package: backend/ in the repo,
# /srv in the container, /var/task/backend on Vercel. Shipped config lives under it.
BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_ROOT.parent
MIN_HMAC_KEY_BYTES = 32

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _split_csv(value: object) -> object:
    """Accept comma-separated strings for list settings (env-friendly)."""
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DSN_",
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
        frozen=True,
    )

    # --- Runtime ---------------------------------------------------------------
    env: Literal["development", "test", "production"] = "development"
    # "lab": runs next to the lab network (docker-compose) and may enforce.
    # "hosted": serverless/cloud (e.g. Vercel). It cannot reach the lab, so it is
    # pinned to dry-run and never touches a network.
    deployment: Literal["lab", "hosted"] = "lab"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True
    dry_run: bool = True
    offline_mode: bool = True

    # --- Identity --------------------------------------------------------------
    device_id_hmac_key: SecretStr

    # --- API -------------------------------------------------------------------
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )

    # --- Lab network -----------------------------------------------------------
    lab_cidr: IPNetwork = ipaddress.IPv4Network("192.168.50.0/24")
    protected_hosts: Annotated[list[IPAddress], NoDecode] = Field(default_factory=list)

    # --- Storage ---------------------------------------------------------------
    database_url: str = "sqlite:///./data/dsn.sqlite3"
    neo4j_uri: str | None = None
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr | None = None

    # --- MQTT ------------------------------------------------------------------
    mqtt_host: str | None = None
    mqtt_port: int = Field(default=8883, ge=1, le=65535)
    mqtt_username: str | None = None
    mqtt_password: SecretStr | None = None

    # --- Feeds -----------------------------------------------------------------
    feeds_config_path: Path = BACKEND_ROOT / "config" / "feeds.yaml"
    fixtures_dir: Path = REPO_ROOT / "fixtures"
    cache_dir: Path = Path("./data/cache")
    scheduler_enabled: bool = True
    http_user_agent: str = "DarknetSentinelNexus/0.1 (defensive threat-intel client)"
    nvd_api_key: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None
    # Generic licensed dark-web intel provider (REST/JSON).
    darkweb_api_url: str | None = None
    darkweb_api_key: SecretStr | None = None
    darkweb_auth_header: str = "Authorization"
    darkweb_auth_scheme: str = "Bearer"  # empty string sends the bare key
    darkweb_items_path: str = "data"  # dot path to the list of mentions
    # Our field -> provider field (dot paths). JSON object in env.
    darkweb_field_map: dict[str, str] = Field(
        default_factory=lambda: {
            "id": "id",
            "source": "source",
            "published": "published_at",
            "text": "text",
        }
    )

    # --- Devices & behavior (Phase 2) -------------------------------------------
    devices_config_path: Path = BACKEND_ROOT / "config" / "devices.yaml"
    rules_config_path: Path = BACKEND_ROOT / "config" / "rules.yaml"
    behavior_config_path: Path = BACKEND_ROOT / "config" / "behavior.yaml"
    models_dir: Path = Path("./data/models")
    # Train the Isolation Forest at startup when no (valid) model exists.
    iforest_autotrain: bool = True
    risk_config_path: Path = BACKEND_ROOT / "config" / "risk.yaml"
    # Train the XGBoost comparison model at startup when no valid model exists.
    xgb_autotrain: bool = True
    nmap_interval_minutes: int = Field(default=30, ge=5)
    # Discovery sources. Each also needs a runtime capability check to start.
    # Active nmap scans additionally require DSN_DRY_RUN=false.
    nmap_enabled: bool = False
    passive_capture_enabled: bool = False
    passive_capture_iface: str | None = None
    ble_scan_enabled: bool = False
    # Wi-Fi management-frame monitoring needs a monitor-mode interface and
    # DSN_DRY_RUN=false (it is treated like scanning).
    wifi_monitor_enabled: bool = False
    wifi_monitor_iface: str | None = None

    # --- Response (Phase 4) -----------------------------------------------------
    # Which firewall to drive when DRY_RUN is false. DRY_RUN=true always uses the
    # dry-run driver regardless of this setting.
    response_driver: Literal["nftables", "iptables", "dryrun"] = "nftables"
    # Quarantine automatically when the risk engine recommends it (CRITICAL).
    auto_quarantine: bool = True
    quarantine_minutes: int = Field(default=30, ge=1, le=7 * 24 * 60)
    # Threat model E1: refuse to quarantine more devices than this at once.
    max_active_quarantines: int = Field(default=10, ge=1, le=1000)
    # Bearer token for mutating API calls (manual quarantine/release/approve).
    # Unset -> mutations are disabled. Interim until Phase 6 user auth.
    admin_token: SecretStr | None = None
    # MQTT client options and the key that signs status-node commands.
    mqtt_tls: bool = True
    mqtt_ca_file: str | None = None
    mqtt_command_key: SecretStr | None = None

    # --- Validators ------------------------------------------------------------
    @field_validator("cors_origins", "protected_hosts", mode="before")
    @classmethod
    def _csv(cls, value: object) -> object:
        return _split_csv(value)

    @field_validator("device_id_hmac_key")
    @classmethod
    def _hmac_key_strength(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode("utf-8")) < MIN_HMAC_KEY_BYTES:
            raise ValueError(f"must be at least {MIN_HMAC_KEY_BYTES} bytes")
        return value

    @field_validator("cors_origins")
    @classmethod
    def _cors_explicit(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            parsed = urlparse(origin)
            if "*" in origin or parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"CORS origin must be an explicit http(s) origin: {origin!r}")
            if parsed.path not in {"", "/"}:
                raise ValueError(f"CORS origin must not contain a path: {origin!r}")
        return [o.rstrip("/") for o in origins]

    @field_validator("lab_cidr")
    @classmethod
    def _lab_is_private(cls, network: IPNetwork) -> IPNetwork:
        # Guardrail: the platform may only scan/enforce on private address space.
        if not network.is_private or network.is_loopback:
            raise ValueError(f"lab_cidr must be a private, non-loopback network: {network}")
        return network

    @field_validator("darkweb_api_url")
    @classmethod
    def _darkweb_https(cls, url: str | None) -> str | None:
        if url is not None and urlparse(url).scheme != "https":
            raise ValueError("darkweb_api_url must use https")
        return url

    @field_validator("admin_token", "mqtt_command_key")
    @classmethod
    def _strong_secret(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < MIN_HMAC_KEY_BYTES:
            raise ValueError(f"must be at least {MIN_HMAC_KEY_BYTES} characters")
        return value

    @field_validator("darkweb_field_map")
    @classmethod
    def _field_map_complete(cls, mapping: dict[str, str]) -> dict[str, str]:
        missing = {"id", "text"} - mapping.keys()
        if missing:
            raise ValueError(f"darkweb_field_map must map {sorted(missing)}")
        return mapping

    @model_validator(mode="after")
    def _paired_credentials(self) -> Settings:
        if self.deployment == "hosted" and not self.dry_run:
            raise ValueError("hosted deployments are dry-run only; enforcement requires 'lab'")
        if self.neo4j_uri and self.neo4j_password is None:
            raise ValueError("neo4j_password is required when neo4j_uri is set")
        if self.mqtt_host and (self.mqtt_username is None or self.mqtt_password is None):
            raise ValueError("mqtt_username and mqtt_password are required when mqtt_host is set")
        if self.darkweb_api_url and self.darkweb_api_key is None:
            raise ValueError("darkweb_api_key is required when darkweb_api_url is set")
        if self.env == "production":
            insecure = [o for o in self.cors_origins if not o.startswith("https://")]
            if insecure:
                raise ValueError(f"production CORS origins must be https: {insecure}")
        return self

    # --- Helpers ---------------------------------------------------------------
    def secret_values(self) -> list[str]:
        """All configured secret values, for log redaction."""
        values: list[str] = []
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, SecretStr) and value.get_secret_value():
                values.append(value.get_secret_value())
        return values

    def is_protected(self, host: IPAddress) -> bool:
        return host in self.protected_hosts


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    # Required fields are populated from the environment by pydantic-settings.
    return Settings()
