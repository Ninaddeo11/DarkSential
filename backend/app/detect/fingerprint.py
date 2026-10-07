"""Service fingerprint -> CPE 2.3 guesses (with confidence).

Order of preference:
1. CPEs nmap itself reports (``-sV`` emits CPE 2.2 URIs), converted to 2.3.
2. A small product table for services common on IoT/lab gear, filled in with
   the detected version.
Guesses feed ``cves_for_cpe`` in Phase 3; confidence travels with them so the
risk engine can discount weak guesses.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

from app.detect.observations import Service

# Lowercased nmap product (prefix) -> (part, vendor, product) in CPE terms.
PRODUCT_CPE: dict[str, tuple[str, str, str]] = {
    "mosquitto": ("a", "eclipse", "mosquitto"),
    "openssh": ("a", "openbsd", "openssh"),
    "dropbear sshd": ("a", "dropbear_ssh_project", "dropbear_ssh"),
    "lighttpd": ("a", "lighttpd", "lighttpd"),
    "nginx": ("a", "f5", "nginx"),
    "apache httpd": ("a", "apache", "http_server"),
    "boa httpd": ("a", "boa", "boa"),
    "goahead webs": ("a", "embedthis", "goahead"),
    "micro_httpd": ("a", "acme", "micro_httpd"),
    "mini_httpd": ("a", "acme", "mini_httpd"),
    "busybox telnetd": ("a", "busybox", "busybox"),
    "dnsmasq": ("a", "thekelleys", "dnsmasq"),
    "miniupnpd": ("a", "miniupnp_project", "miniupnpd"),
}

_CPE22 = re.compile(r"^cpe:/([aho]):([^:]+):([^:]+)(?::([^:]*))?")
_SAFE = re.compile(r"[^a-z0-9._\-~%]")


def _escape(value: str) -> str:
    """CPE 2.3 formatted-string escaping for free-text components."""
    value = value.strip().lower().replace(" ", "_")
    return _SAFE.sub(lambda m: "\\" + m.group(), value) or "*"


def cpe22_to_23(uri: str) -> str | None:
    """CPE 2.2 URI -> 2.3 formatted string (percent-decoding, then 2.3 escaping).

    nmap writes ``/`` inside a component as ``%2f``; NVD's 2.3 form escapes it
    with a backslash instead.
    """
    m = _CPE22.match(uri.strip().lower())
    if not m:
        return None
    part, vendor, product, version = (unquote(g) if g else g for g in m.groups())
    fields = [part, _escape(vendor), _escape(product), _escape(version) if version else "*"]
    return "cpe:2.3:" + ":".join(fields + ["*"] * 7)


def guess_cpes(services: list[Service], host_cpes: list[str] | None = None) -> list[dict[str, Any]]:
    guesses: dict[str, dict[str, Any]] = {}

    def add(cpe: str, confidence: float, basis: str, service: Service) -> None:
        current = guesses.get(cpe)
        if current is None or current["confidence"] < confidence:
            guesses[cpe] = {
                "cpe": cpe,
                "confidence": confidence,
                "basis": basis,
                "service": service.key,
            }

    host = Service(port=0, name="host")
    for raw in host_cpes or []:
        cpe = raw if raw.startswith("cpe:2.3:") else cpe22_to_23(raw)
        if cpe:
            versioned = cpe.split(":")[5] not in {"*", "-", ""}
            add(cpe, 0.8 if versioned else 0.5, "nmap-os", host)
    for svc in services:
        for raw in svc.cpe:
            cpe = raw if raw.startswith("cpe:2.3:") else cpe22_to_23(raw)
            if cpe:
                versioned = cpe.split(":")[5] not in {"*", "-", ""}
                add(cpe, 0.9 if versioned else 0.6, "nmap-cpe", svc)
        product = (svc.product or "").lower()
        for prefix, (part, vendor, prod) in PRODUCT_CPE.items():
            if product.startswith(prefix):
                version = _escape(svc.version) if svc.version else "*"
                cpe = f"cpe:2.3:{part}:{vendor}:{prod}:{version}:*:*:*:*:*:*:*"
                add(cpe, 0.7 if svc.version else 0.4, "product-table", svc)
                break
    # One guess per (part, vendor, product): the most confident wins.
    best: dict[str, dict[str, Any]] = {}
    for g in sorted(guesses.values(), key=lambda g: (-g["confidence"], g["cpe"])):
        best.setdefault(":".join(g["cpe"].split(":")[2:5]), g)
    return sorted(best.values(), key=lambda g: (-g["confidence"], g["cpe"]))
