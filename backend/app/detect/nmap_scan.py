"""nmap discovery: ping sweep and service/version scan of the lab CIDR only.

Safety:
* Every target must be inside ``lab_cidr`` (checked with ``ipaddress``, so no
  string tricks), and scan arguments come from fixed profiles, never from input.
* Under DRY_RUN the scanner returns the planned command and does not scan.
* Output is parsed with ``defusedxml``; banners inside it are device-controlled.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Literal

from defusedxml import ElementTree

from app.core.config import Settings
from app.detect.observations import Observation, Service

log = logging.getLogger(__name__)

Profile = Literal["ping", "service"]
PROFILES: dict[Profile, list[str]] = {
    "ping": ["-sn", "-n"],
    "service": [
        "-sV",
        "-n",
        "--top-ports",
        "200",
        "-T3",
        "--max-retries",
        "2",
        "--host-timeout",
        "120s",
    ],
}


class ScanTargetError(ValueError):
    pass


@dataclass
class ScanResult:
    dry_run: bool
    command: list[str]
    observations: list[Observation] = field(default_factory=list)


def validate_targets(settings: Settings, targets: list[str] | None) -> list[str]:
    lab = settings.lab_cidr
    out: list[str] = []
    for raw in targets or [str(lab)]:
        try:
            net = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError as exc:
            raise ScanTargetError(f"invalid scan target {raw!r}") from exc
        if net.version != lab.version or not net.subnet_of(lab):  # type: ignore[arg-type]
            raise ScanTargetError(f"target {net} is outside lab_cidr {lab}")
        out.append(str(net))
    return out


def plan(settings: Settings, profile: Profile, targets: list[str] | None = None) -> list[str]:
    return ["nmap", *PROFILES[profile], "-oX", "-", *validate_targets(settings, targets)]


def scan(settings: Settings, profile: Profile, targets: list[str] | None = None) -> ScanResult:
    command = plan(settings, profile, targets)
    if settings.dry_run or not settings.nmap_enabled:
        log.info("nmap scan not executed", extra={"dry_run": settings.dry_run, "command": command})
        return ScanResult(dry_run=True, command=command)
    import nmap  # lab extra

    scanner = nmap.PortScanner()
    hosts = " ".join(command[len(PROFILES[profile]) + 3 :])
    scanner.scan(hosts=hosts, arguments=" ".join(PROFILES[profile]))
    return ScanResult(
        dry_run=False, command=command, observations=parse_nmap_xml(scanner.get_nmap_last_output())
    )


def parse_nmap_xml(xml: str | bytes) -> list[Observation]:
    root = ElementTree.fromstring(xml)
    observations: list[Observation] = []
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        mac = ip = vendor = None
        for addr in host.findall("address"):
            kind = addr.get("addrtype")
            if kind == "mac":
                mac, vendor = addr.get("addr"), addr.get("vendor")
            elif kind in {"ipv4", "ipv6"} and ip is None:
                ip = addr.get("addr")
        hostname_el = host.find("hostnames/hostname")
        services: list[Service] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            services.append(
                Service(
                    port=int(port.get("portid", "0")),
                    proto="udp" if port.get("protocol") == "udp" else "tcp",
                    name=svc.get("name") if svc is not None else None,
                    product=svc.get("product") if svc is not None else None,
                    version=svc.get("version") if svc is not None else None,
                    cpe=[c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text],
                )
            )
        attrs: dict[str, object] = {}
        if vendor:
            attrs["nmap_vendor"] = vendor
        os_match = host.find("os/osmatch")
        host_cpes: list[str] = []
        if os_match is not None and os_match.get("name"):
            attrs["os_guess"] = os_match.get("name")
            host_cpes = [c.text for c in os_match.findall("osclass/cpe") if c.text][:16]
        observations.append(
            Observation(
                source="nmap",
                mac=mac,
                ip=ip,
                hostname=hostname_el.get("name") if hostname_el is not None else None,
                services=services,
                host_cpes=host_cpes,
                attributes=attrs,
            )
        )
    return observations
