"""Passive discovery from ARP, DHCP and mDNS (listen-only, never transmits).

``observation_from_packet`` is a pure function over scapy packets, so it is
fully testable with crafted packets. ``PassiveObserver`` wraps scapy's
AsyncSniffer and starts only when enabled and the host has capture rights.

With a traffic sink (``DSN_PASSIVE_CAPTURE_TRAFFIC``, e.g. on the virtual lab's
gateway) the same sniffer also turns every IP packet into ``TrafficEvent``s via
``events_from_packets``, batched so the behavior pipeline takes one lock per
batch rather than per packet.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from app.core.identifiers import normalize_mac
from app.detect.observations import Observation

if TYPE_CHECKING:
    from app.behavior.events import TrafficEvent

log = logging.getLogger(__name__)

BPF_FILTER = "arp or (udp and (port 67 or port 68 or port 5353))"
TRAFFIC_BPF_FILTER = "arp or ip"
TRAFFIC_BATCH_SECONDS = 1.0
TRAFFIC_BATCH_MAX = 500
_MDNS_PORT = 5353
_DNS_A, _DNS_PTR, _DNS_SRV = 1, 12, 33
UNSPECIFIED = "0.0.0.0"  # noqa: S104 - compared against, never bound


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).rstrip(".") or None


def _mac(value: Any) -> str | None:
    try:
        return normalize_mac(str(value))
    except ValueError:
        return None


def observation_from_packet(pkt: Any) -> Observation | None:
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import ARP, Ether

    if ARP in pkt:
        arp = pkt[ARP]
        if arp.op not in (1, 2) or arp.psrc in (UNSPECIFIED, None):
            return None
        return Observation(source="arp", mac=_mac(arp.hwsrc), ip=arp.psrc)

    if DHCP in pkt and BOOTP in pkt:
        bootp = pkt[BOOTP]
        options = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple) and len(o) >= 2}
        mac = _mac(":".join(f"{b:02x}" for b in bytes(bootp.chaddr)[:6]))
        ip = _text(options.get("requested_addr")) or (
            bootp.ciaddr if bootp.ciaddr != UNSPECIFIED else None
        )
        if bootp.op == 2:  # server reply: yiaddr is the client's address
            ip = bootp.yiaddr if bootp.yiaddr != UNSPECIFIED else None
        attrs: dict[str, Any] = {}
        if options.get("vendor_class_id"):
            attrs["dhcp_vendor_class"] = _text(options["vendor_class_id"])
        if options.get("param_req_list"):
            # The parameter request list is a well-known OS/device fingerprint.
            attrs["dhcp_prl"] = ",".join(str(x) for x in list(options["param_req_list"])[:32])
        return Observation(
            source="dhcp",
            mac=mac,
            ip=ip,
            hostname=_text(options.get("hostname")),
            attributes=attrs,
        )

    if UDP in pkt and DNS in pkt and _MDNS_PORT in (pkt[UDP].sport, pkt[UDP].dport):
        dns = pkt[DNS]
        if not dns.qr:  # queries reveal little; answers announce the device
            return None
        hostname = ip = None
        services: list[str] = []
        records = list(_records(dns.an)) + list(_records(dns.ar))
        for rr in records:
            name = _text(getattr(rr, "rrname", None))
            if rr.type == _DNS_A:
                hostname, ip = name, _text(rr.rdata)
            elif rr.type == _DNS_PTR and name and name.startswith("_"):
                services.append(name)
            elif rr.type == _DNS_SRV:
                hostname = hostname or _text(getattr(rr, "target", None))
        src_mac = _mac(pkt[Ether].src) if Ether in pkt else None
        src_ip = pkt[IP].src if IP in pkt else None
        attrs = {"mdns_services": sorted(set(services))[:16]} if services else {}
        return Observation(
            source="mdns",
            mac=src_mac,
            ip=ip or src_ip,
            hostname=hostname.removesuffix(".local") if hostname else None,
            attributes=attrs,
        )
    return None


def _records(section: Any) -> list[Any]:
    """Flatten a DNS record section.

    Depending on how a packet was built or dissected, scapy stores records as a
    list, as a payload chain (rr / rr / rr), or as a list whose elements carry
    payload chains, so walk both. Capped at 64 records (hostile packets).
    """
    if section is None:
        return []
    heads = section if isinstance(section, list) else [section]
    out: list[Any] = []
    for head in heads:
        rr = head
        while rr is not None and getattr(rr, "type", None) is not None and len(out) < 64:
            out.append(rr)
            rr = rr.payload if rr.payload else None
    return out


class PassiveObserver:
    def __init__(
        self,
        on_observation: Callable[[Observation], object],
        iface: str | None,
        on_traffic: Callable[[list[TrafficEvent]], object] | None = None,
        clock: Callable[[], float] = time.monotonic,
        ignore_ips: frozenset[str] | None = None,
    ) -> None:
        self._on = on_observation
        # This host's own addresses: DSN must not profile itself (e.g. its own
        # nmap scans seen on the capture interface). None = resolve at start().
        self._ignore: frozenset[str] = ignore_ips or frozenset()
        self._resolve_ignore = ignore_ips is None
        self._iface = iface
        self._on_traffic = on_traffic
        self._clock = clock
        self._sniffer: Any = None
        self._batch: list[TrafficEvent] = []
        self._batch_started = 0.0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._flusher: threading.Thread | None = None

    def _handle(self, pkt: Any) -> None:
        try:
            obs = observation_from_packet(pkt)
        except Exception:  # malformed packets must never kill the sniffer
            log.debug("unparseable packet", exc_info=True)
            obs = None
        if obs is not None and obs.ip not in self._ignore:
            self._on(obs)
        if self._on_traffic is not None:
            self._collect(pkt)

    def _collect(self, pkt: Any) -> None:
        from app.behavior.pcap import events_from_packets

        try:
            events = list(events_from_packets([pkt]))
        except Exception:
            log.debug("unparseable packet", exc_info=True)
            return
        events = [e for e in events if e.src_ip not in self._ignore]
        with self._lock:
            if events and not self._batch:
                self._batch_started = self._clock()
            self._batch.extend(events)
            due = self._batch and (
                len(self._batch) >= TRAFFIC_BATCH_MAX
                or self._clock() - self._batch_started >= TRAFFIC_BATCH_SECONDS
            )
        if due:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            batch, self._batch = self._batch, []
        if batch and self._on_traffic is not None:
            self._on_traffic(batch)

    def start(self) -> None:
        # Importing the layer modules registers their link-type bindings (Ethernet
        # for ARPHRD_ETHER, IP/TCP/UDP, DNS). Without them a live socket can't
        # decode frames and hands back raw ``Packet``s ("Unable to guess type"),
        # which every parser here silently ignores.
        import scapy.layers.dns
        import scapy.layers.inet
        import scapy.layers.l2  # noqa: F401
        from scapy.sendrecv import AsyncSniffer

        if self._resolve_ignore and self._iface:
            from scapy.arch import get_if_addr

            try:
                own = get_if_addr(self._iface)
            except Exception:  # unknown iface: capture still starts, nothing ignored
                log.warning("cannot resolve capture interface address", exc_info=True)
                own = UNSPECIFIED
            self._ignore = frozenset({own} - {UNSPECIFIED})
        bpf = TRAFFIC_BPF_FILTER if self._on_traffic is not None else BPF_FILTER
        self._sniffer = AsyncSniffer(iface=self._iface, filter=bpf, prn=self._handle, store=False)
        self._sniffer.start()
        if self._on_traffic is not None:
            # Quiet periods must not strand a partial batch (detection latency).
            self._stop.clear()
            self._flusher = threading.Thread(target=self._flush_loop, daemon=True)
            self._flusher.start()
        log.info(
            "passive capture started",
            extra={"iface": self._iface, "traffic": self._on_traffic is not None},
        )

    def _flush_loop(self) -> None:
        while not self._stop.wait(TRAFFIC_BATCH_SECONDS):
            try:
                self.flush()
            except Exception:
                log.exception("traffic batch flush failed")

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
        if self._flusher is not None:
            self._flusher.join(timeout=5)
            self._flusher = None
        self.flush()
