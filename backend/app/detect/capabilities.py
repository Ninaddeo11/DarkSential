"""Runtime capability checks for discovery sources.

Each source runs only when (a) its config flag is on, (b) the host can actually
do it, and (c) for active or monitor-mode techniques, DRY_RUN is off. The report
is exposed read-only at /api/discovery/capabilities so the operator can see why
a source is idle.
"""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
from pathlib import Path

from pydantic import BaseModel

from app.core.config import Settings

_CAP_NET_RAW = 13
_ARPHRD_IEEE80211_RADIOTAP = "803"


class SourceStatus(BaseModel):
    enabled: bool
    available: bool
    active: bool
    reason: str


def is_privileged() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0 or _has_cap_net_raw()
    try:  # Windows
        import ctypes

        admin = ctypes.windll.shell32.IsUserAnAdmin()  # type: ignore[attr-defined,unused-ignore]
        return bool(admin)
    except (AttributeError, OSError):
        return False


def _has_cap_net_raw() -> bool:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                return bool(int(line.split()[1], 16) & (1 << _CAP_NET_RAW))
    except (OSError, ValueError, IndexError):
        pass
    return False


def is_monitor_iface(iface: str) -> bool:
    if platform.system() != "Linux" or "/" in iface or iface in {"", ".", ".."}:
        return False
    try:
        return Path(f"/sys/class/net/{iface}/type").read_text().strip() == (
            _ARPHRD_IEEE80211_RADIOTAP
        )
    except OSError:
        return False


def _status(enabled: bool, checks: list[tuple[bool, str]], name: str) -> SourceStatus:
    for ok, reason in checks:
        if not ok:
            return SourceStatus(enabled=enabled, available=False, active=False, reason=reason)
    if not enabled:
        return SourceStatus(
            enabled=False, available=True, active=False, reason=f"{name} disabled in config"
        )
    return SourceStatus(enabled=True, available=True, active=True, reason="ok")


def report(settings: Settings) -> dict[str, SourceStatus]:
    privileged = is_privileged()
    return {
        "nmap": _status(
            settings.nmap_enabled,
            [
                (shutil.which("nmap") is not None, "nmap binary not found"),
                (not settings.dry_run, "DRY_RUN: active scans only print their plan"),
            ],
            "DSN_NMAP_ENABLED",
        ),
        "passive": _status(
            settings.passive_capture_enabled,
            [
                (importlib.util.find_spec("scapy") is not None, "scapy not installed"),
                (privileged, "packet capture needs root/CAP_NET_RAW (or Npcap admin)"),
            ],
            "DSN_PASSIVE_CAPTURE_ENABLED",
        ),
        "ble": _status(
            settings.ble_scan_enabled,
            [(importlib.util.find_spec("bleak") is not None, "bleak not installed")],
            "DSN_BLE_SCAN_ENABLED",
        ),
        "wifi": _status(
            settings.wifi_monitor_enabled,
            [
                (bool(settings.wifi_monitor_iface), "DSN_WIFI_MONITOR_IFACE not set"),
                (
                    is_monitor_iface(settings.wifi_monitor_iface or ""),
                    "interface is not in monitor mode (Linux radiotap required)",
                ),
                (privileged, "monitor capture needs root/CAP_NET_RAW"),
                (not settings.dry_run, "DRY_RUN: Wi-Fi monitoring is off"),
            ],
            "DSN_WIFI_MONITOR_ENABLED",
        ),
    }
