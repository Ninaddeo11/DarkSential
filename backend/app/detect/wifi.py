"""Wi-Fi management-frame monitoring: deauthentication/disassociation rate per BSSID.

A burst of deauth frames against an AP is the classic Wi-Fi DoS (and the
first step of handshake capture). Monitoring needs a monitor-mode interface,
root, and DRY_RUN off (see capabilities.py). Frame handling is a pure
function with an injectable clock, so it is tested with crafted 802.11 frames.
BSSIDs are MACs, so they are HMAC'd before leaving this module.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.core.identifiers import DeviceIdHasher, normalize_mac

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeauthAlert:
    bssid_hmac: str
    frames: int
    rate_per_min: float
    window_seconds: float
    kinds: dict[str, int]


class DeauthMonitor:
    def __init__(
        self,
        hasher: DeviceIdHasher,
        on_alert: Callable[[DeauthAlert], None],
        *,
        window_seconds: float = 60.0,
        threshold_per_min: float = 30.0,
        cooldown_seconds: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._hasher = hasher
        self._on_alert = on_alert
        self._window = window_seconds
        self._threshold = threshold_per_min
        self._cooldown = cooldown_seconds
        self._clock = clock
        self._frames: dict[str, deque[tuple[float, str]]] = {}
        self._last_alert: dict[str, float] = {}
        self._lock = threading.Lock()
        self._sniffer: Any = None

    def handle_frame(self, pkt: Any) -> DeauthAlert | None:
        from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas

        if Dot11 not in pkt or not (Dot11Deauth in pkt or Dot11Disas in pkt):
            return None
        try:
            bssid = normalize_mac(str(pkt[Dot11].addr3))
        except ValueError:
            return None
        kind = "deauth" if Dot11Deauth in pkt else "disassoc"
        now = self._clock()
        with self._lock:
            frames = self._frames.setdefault(bssid, deque())
            frames.append((now, kind))
            while frames and now - frames[0][0] > self._window:
                frames.popleft()
            rate = len(frames) / self._window * 60.0
            last = self._last_alert.get(bssid)
            if rate < self._threshold or (last is not None and now - last < self._cooldown):
                return None
            self._last_alert[bssid] = now
            kinds: dict[str, int] = {}
            for _, k in frames:
                kinds[k] = kinds.get(k, 0) + 1
        alert = DeauthAlert(
            bssid_hmac=self._hasher.device_id(bssid),
            frames=len(frames),
            rate_per_min=round(rate, 2),
            window_seconds=self._window,
            kinds=kinds,
        )
        self._on_alert(alert)
        return alert

    def start(self, iface: str) -> None:
        from scapy.sendrecv import AsyncSniffer

        def safe(pkt: Any) -> None:
            try:
                self.handle_frame(pkt)
            except Exception:
                log.debug("bad 802.11 frame", exc_info=True)

        self._sniffer = AsyncSniffer(iface=iface, prn=safe, store=False, monitor=True)
        self._sniffer.start()
        log.info("wifi deauth monitoring started", extra={"iface": iface})

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
