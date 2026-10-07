"""BLE discovery from advertisements (bleak, passive scan only; never connects).

Advertising names and manufacturer data are attacker-controllable; they are
sanitized by ``Observation``. Most BLE devices use random addresses that
rotate, so a BLE identity is weaker than a Wi-Fi/Ethernet MAC (documented).
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable
from typing import Any

from app.core.identifiers import normalize_mac
from app.detect.observations import Observation

log = logging.getLogger(__name__)


def observation_from_advertisement(device: Any, adv: Any) -> Observation:
    address = str(getattr(device, "address", ""))
    try:
        mac: str | None = normalize_mac(address)
        alt_id = None
    except ValueError:  # macOS reports per-host UUIDs instead of MACs
        mac, alt_id = None, f"ble:{address.lower()}"[:128]
    attrs: dict[str, Any] = {
        "ble_rssi": getattr(adv, "rssi", None),
        "ble_tx_power": getattr(adv, "tx_power", None),
        "ble_manufacturer_ids": sorted(int(k) for k in (adv.manufacturer_data or {}))[:16],
        "ble_service_uuids": sorted(str(u) for u in (adv.service_uuids or []))[:16],
    }
    return Observation(
        source="ble",
        mac=mac,
        alt_id=alt_id,
        hostname=getattr(adv, "local_name", None),
        attributes={k: v for k, v in attrs.items() if v not in (None, [])},
    )


class BleScanner:
    """Runs bleak's scanner on a private event loop in a daemon thread."""

    def __init__(self, on_observation: Callable[[Observation], object]) -> None:
        self._on = on_observation
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._thread: threading.Thread | None = None

    def _callback(self, device: Any, adv: Any) -> None:
        try:
            self._on(observation_from_advertisement(device, adv))
        except Exception:
            log.debug("bad BLE advertisement", exc_info=True)

    async def _run(self) -> None:
        from bleak import BleakScanner

        self._stop = asyncio.Event()
        async with BleakScanner(detection_callback=self._callback, scanning_mode="passive"):
            await self._stop.wait()

    def start(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_until_complete, args=(self._run(),), daemon=True
        )
        self._thread.start()
        log.info("BLE scanning started")

    def stop(self) -> None:
        if self._loop and self._stop:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread:
            self._thread.join(timeout=5)
