"""STIX 2.1 object construction and validation (``stix2`` library).

Design rules:
- **Deterministic IDs** (UUIDv5 over a natural key) so the same CVE from KEV and
  NVD, or the same IP from two feeds, converge on one object and one graph node.
- **Untrusted values are escaped** before going into STIX patterns, so a value
  containing quotes cannot break or alter the pattern (pattern injection).
- **Every object is validated** by round-tripping through ``stix2.parse``.
- Observables are also recorded in ``x_dsn_observables`` so the graph layer
  never has to re-parse patterns.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import stix2

DSN_NAMESPACE = uuid.UUID("5f8a1c2e-3d4b-4e6f-9a0b-1c2d3e4f5a6b")

ObservableType = Literal[
    "ipv4-addr", "ipv6-addr", "domain-name", "url", "file-md5", "file-sha1", "file-sha256"
]
_HASH_PATH = {
    "file-md5": "file:hashes.MD5",
    "file-sha1": "file:hashes.'SHA-1'",
    "file-sha256": "file:hashes.'SHA-256'",
}
_HASH_LEN = {"file-md5": 32, "file-sha1": 40, "file-sha256": 64}
_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def stix_id(stix_type: str, natural_key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(DSN_NAMESPACE, f'{stix_type}:{natural_key}')}"


def name_key(name: str) -> str:
    """Case/space-insensitive key for matching names across sources."""
    return re.sub(r"\s+", " ", name).strip().casefold()


def escape_pattern_value(value: str) -> str:
    """Escape a string literal for a STIX pattern (backslash first, then quote)."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


@dataclass(frozen=True)
class Observable:
    type: ObservableType
    value: str

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"

    def as_dict(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value}


def make_observable(obs_type: ObservableType, raw: str) -> Observable:
    """Normalize and validate an observable value; raises ValueError if invalid."""
    value = raw.strip()
    if obs_type in ("ipv4-addr", "ipv6-addr"):
        ip = ipaddress.ip_address(value)
        if (obs_type == "ipv4-addr") != (ip.version == 4):
            raise ValueError(f"{value!r} is not {obs_type}")
        return Observable(obs_type, ip.compressed)
    if obs_type == "domain-name":
        domain = value.rstrip(".").lower()
        if not _DOMAIN.fullmatch(domain):
            raise ValueError(f"invalid domain {value!r}")
        return Observable(obs_type, domain)
    if obs_type == "url":
        if not re.match(r"^[a-z][a-z0-9+.-]*://\S+$", value, re.I) or len(value) > 2048:
            raise ValueError("invalid url")
        return Observable(obs_type, value)
    digest = value.lower()
    if len(digest) != _HASH_LEN[obs_type] or not _HEX.fullmatch(digest):
        raise ValueError(f"invalid {obs_type}")
    return Observable(obs_type, digest)


def observable_from_host(host: str) -> Observable:
    """IP literal or domain name."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return make_observable("domain-name", host)
    return make_observable("ipv4-addr" if ip.version == 4 else "ipv6-addr", ip.compressed)


def pattern_for(obs: Observable, port: int | None = None) -> str:
    value = escape_pattern_value(obs.value)
    if obs.type in ("ipv4-addr", "ipv6-addr"):
        if port is None:
            return f"[{obs.type}:value = '{value}']"
        return (
            f"[network-traffic:dst_ref.type = '{obs.type}' AND "
            f"network-traffic:dst_ref.value = '{value}' AND network-traffic:dst_port = {int(port)}]"
        )
    if obs.type in _HASH_PATH:
        return f"[{_HASH_PATH[obs.type]} = '{value}']"
    return f"[{obs.type}:value = '{value}']"


def to_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


_TS_FORMATS = ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


def parse_timestamp(value: object) -> datetime | None:
    """Parse the timestamp shapes used by our feeds; None if absent/unparseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        return to_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        return None


def _clamp_confidence(value: float) -> int:
    return max(0, min(100, round(value)))


# --- Builders -------------------------------------------------------------------


def build_indicator(
    obs: Observable,
    *,
    source: str,
    confidence: float,
    valid_from: datetime,
    port: int | None = None,
    name: str | None = None,
    description: str | None = None,
    labels: list[str] | None = None,
    valid_until: datetime | None = None,
) -> stix2.v21.Indicator:
    key = obs.key if port is None else f"{obs.key}:{port}"
    kwargs: dict[str, Any] = {}
    if valid_until is not None and valid_until > valid_from:
        kwargs["valid_until"] = valid_until
    return stix2.v21.Indicator(
        id=stix_id("indicator", key),
        name=name or f"{obs.type} {obs.value}"[:256],
        description=description,
        pattern=pattern_for(obs, port),
        pattern_type="stix",
        valid_from=to_utc(valid_from),
        created=to_utc(valid_from),
        modified=to_utc(valid_from),
        indicator_types=["malicious-activity"],
        labels=sorted({label.lower()[:64] for label in labels or [] if label}) or None,
        confidence=_clamp_confidence(confidence),
        custom_properties={
            "x_dsn_observables": [obs.as_dict()],
            "x_dsn_port": port,
            "x_dsn_source": source,
        },
        **kwargs,
    )


def build_vulnerability(
    cve: str,
    *,
    source: str,
    confidence: float,
    created: datetime,
    modified: datetime | None = None,
    description: str | None = None,
    cvss: dict[str, Any] | None = None,
    cpe_matches: list[dict[str, Any]] | None = None,
    kev: dict[str, Any] | None = None,
) -> stix2.v21.Vulnerability:
    cve = cve.strip().upper()
    if not CVE_RE.fullmatch(cve):
        raise ValueError(f"invalid CVE id {cve!r}")
    created = to_utc(created)
    modified = max(created, to_utc(modified or created))
    custom: dict[str, Any] = {"x_dsn_source": source}
    if cvss:
        custom["x_dsn_cvss"] = cvss
    if cpe_matches:
        custom["x_dsn_cpe_matches"] = cpe_matches
    if kev:
        custom["x_dsn_kev"] = kev
    return stix2.v21.Vulnerability(
        id=stix_id("vulnerability", cve),
        name=cve,
        description=description,
        created=created,
        modified=modified,
        confidence=_clamp_confidence(confidence),
        external_references=[
            {
                "source_name": "cve",
                "external_id": cve,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            }
        ],
        custom_properties=custom,
    )


def build_malware(
    name: str, *, source: str, confidence: float, aliases: list[str] | None = None
) -> stix2.v21.Malware:
    clean = re.sub(r"\s+", " ", name).strip()[:256]
    alias_set = sorted({a.strip() for a in aliases or [] if a.strip() and a.strip() != clean})
    return stix2.v21.Malware(
        id=stix_id("malware", name_key(clean)),
        name=clean,
        is_family=True,
        aliases=[clean, *alias_set],
        confidence=_clamp_confidence(confidence),
        custom_properties={"x_dsn_source": source},
    )


def build_relationship(
    source_ref: str, relationship_type: str, target_ref: str, *, confidence: float, source: str
) -> stix2.v21.Relationship:
    return stix2.v21.Relationship(
        id=stix_id("relationship", f"{source_ref}|{relationship_type}|{target_ref}"),
        source_ref=source_ref,
        relationship_type=relationship_type,
        target_ref=target_ref,
        confidence=_clamp_confidence(confidence),
        custom_properties={"x_dsn_source": source},
    )


def build_source_identity(source_name: str) -> stix2.v21.Identity:
    return stix2.v21.Identity(
        id=stix_id("identity", f"intel-source:{name_key(source_name)}"),
        name=source_name[:256],
        identity_class="unknown",
        description="Origin of an ingested intelligence item (unverified).",
    )


def build_report(
    natural_key: str,
    *,
    name: str,
    published: datetime,
    object_refs: list[str],
    source: str,
    confidence: float,
    description: str | None = None,
    extra: dict[str, Any] | None = None,
) -> stix2.v21.Report:
    return stix2.v21.Report(
        id=stix_id("report", natural_key),
        name=name[:256],
        published=to_utc(published),
        report_types=["threat-report"],
        object_refs=sorted(set(object_refs)),
        description=description,
        confidence=_clamp_confidence(confidence),
        custom_properties={"x_dsn_source": source, **(extra or {})},
    )


def validate(obj: stix2.base._STIXBase | dict[str, Any]) -> dict[str, Any]:
    """Validate a STIX 2.1 object; returns its JSON-compatible dict.

    Raises ``stix2.exceptions.STIXError`` / ``ValueError`` if invalid.
    """
    data = json.loads(obj.serialize()) if not isinstance(obj, dict) else obj
    if data.get("spec_version", "2.1") != "2.1":
        raise ValueError("only STIX 2.1 objects are accepted")
    parsed = stix2.parse(data, allow_custom=True, version="2.1")
    return dict(json.loads(parsed.serialize()))
