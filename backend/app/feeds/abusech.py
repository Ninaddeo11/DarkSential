"""abuse.ch feeds: URLhaus, ThreatFox, Feodo Tracker -> Indicator (+ Malware) SDOs.

Verification status (2026-10-02):
- Feodo Tracker ipblocklist.json: format VERIFIED live (public, no key).
- URLhaus /v1/urls/recent/ and ThreatFox /api/v1/ get_iocs: both return
  HTTP 401 without an ``Auth-Key`` header (verified). Response shapes follow
  abuse.ch documentation and are UNVERIFIED against a live authenticated
  response; fixtures are synthetic.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.feeds.base import Candidate, FeedAdapter, Rejection
from app.intel.stix import (
    Observable,
    ObservableType,
    build_indicator,
    build_malware,
    build_relationship,
    make_observable,
    observable_from_host,
    parse_timestamp,
)

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

_THREATFOX_TYPES: dict[str, ObservableType] = {
    "domain": "domain-name",
    "url": "url",
    "md5_hash": "file-md5",
    "sha1_hash": "file-sha1",
    "sha256_hash": "file-sha256",
}
_UNKNOWN_MALWARE = {"", "unknown", "unknown malware", "none"}


class _AbuseChAdapter(FeedAdapter):
    def _auth_headers(self) -> dict[str, str]:
        key = self.ctx.settings.abusech_auth_key
        if key is None:
            raise RuntimeError(f"{self.name}: DSN_ABUSECH_AUTH_KEY is required for live mode")
        return {"Auth-Key": key.get_secret_value()}

    def _with_malware(
        self, indicator: Candidate, malware_name: str | None, aliases: list[str], confidence: float
    ) -> Iterable[Candidate]:
        yield indicator
        name = (malware_name or "").strip()
        if name.casefold() in _UNKNOWN_MALWARE:
            return
        malware = build_malware(name, source=self.name, confidence=confidence, aliases=aliases)
        yield malware
        indicator_id = indicator["id"] if isinstance(indicator, dict) else indicator.id
        yield build_relationship(
            indicator_id, "indicates", malware.id, confidence=confidence, source=self.name
        )


class UrlhausAdapter(_AbuseChAdapter):
    name = "urlhaus"

    def fetch(self) -> Any:
        return self._fetcher().fetch_json(URLHAUS_URL, headers=self._auth_headers())

    def candidates(self, raw: Any) -> Iterable[Candidate | Rejection]:
        if raw.get("query_status") not in {"ok", "no_results"}:
            yield Rejection("urlhaus", f"query_status={raw.get('query_status')!r}")
            return
        for item in raw.get("urls") or []:
            ref = f"urlhaus:{item.get('id')}"
            first_seen = parse_timestamp(item.get("date_added")) or self.ctx.clock()
            online = item.get("url_status") == "online"
            confidence = self.confidence if online else self.confidence * 0.7
            labels = [str(t) for t in item.get("tags") or []]
            if item.get("threat"):
                labels.append(str(item["threat"]))
            try:
                url_obs = make_observable("url", str(item.get("url", "")))
                yield build_indicator(
                    url_obs,
                    source=self.name,
                    confidence=confidence,
                    valid_from=first_seen,
                    labels=labels,
                    description=f"URLhaus {item.get('url_status')} ({item.get('threat')})",
                )
                host_obs = observable_from_host(str(item.get("host", "")))
            except ValueError as exc:
                yield Rejection(ref, str(exc))
                continue
            yield build_indicator(
                host_obs,
                source=self.name,
                confidence=confidence * 0.8,  # hosts can be shared/compromised
                valid_from=first_seen,
                labels=labels,
                description="Host serving a URLhaus-listed URL",
            )


def _threatfox_observable(ioc_type: str, ioc: str) -> tuple[Observable, int | None]:
    if ioc_type == "ip:port":
        host, _, port = ioc.rpartition(":")
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError("invalid ip:port")
        obs = observable_from_host(host)
        if obs.type == "domain-name":
            raise ValueError("ip:port with non-IP host")
        return obs, int(port)
    obs_type = _THREATFOX_TYPES.get(ioc_type)
    if obs_type is None:
        raise ValueError(f"unsupported ioc_type {ioc_type!r}")
    return make_observable(obs_type, ioc), None


class ThreatFoxAdapter(_AbuseChAdapter):
    name = "threatfox"

    def fetch(self) -> Any:
        days = max(1, min(int(self.ctx.config.options.get("days", 1)), 7))
        return self._fetcher().fetch_json(
            THREATFOX_URL,
            method="POST",
            headers=self._auth_headers(),
            json_body={"query": "get_iocs", "days": days},
        )

    def candidates(self, raw: Any) -> Iterable[Candidate | Rejection]:
        if raw.get("query_status") not in {"ok", "no_result"}:
            yield Rejection("threatfox", f"query_status={raw.get('query_status')!r}")
            return
        for item in raw.get("data") or []:
            ref = f"threatfox:{item.get('id')}"
            try:
                obs, port = _threatfox_observable(str(item.get("ioc_type")), str(item.get("ioc")))
            except ValueError as exc:
                yield Rejection(ref, str(exc))
                continue
            # Feed confidence caps the provider's self-reported confidence_level.
            provider = item.get("confidence_level")
            confidence = self.confidence * (
                (float(provider) / 100) if isinstance(provider, int | float) else 0.5
            )
            first_seen = parse_timestamp(item.get("first_seen")) or self.ctx.clock()
            indicator = build_indicator(
                obs,
                source=self.name,
                confidence=confidence,
                valid_from=first_seen,
                port=port,
                labels=[str(item.get("threat_type") or ""), *(item.get("tags") or [])],
                description=f"ThreatFox {item.get('threat_type')}: {item.get('malware_printable')}",
            )
            aliases = [a for a in str(item.get("malware_alias") or "").split(",") if a]
            yield from self._with_malware(
                indicator, item.get("malware_printable"), aliases, confidence
            )


class FeodoAdapter(_AbuseChAdapter):
    name = "feodo"

    def fetch(self) -> Any:
        return self._fetcher().fetch_json(FEODO_URL)

    def candidates(self, raw: Any) -> Iterable[Candidate | Rejection]:
        if not isinstance(raw, list):
            yield Rejection("feodo", "expected a JSON list")
            return
        for item in raw:
            ref = f"feodo:{item.get('ip_address')}"
            try:
                obs = observable_from_host(str(item.get("ip_address", "")))
                port = int(item["port"]) if item.get("port") is not None else None
            except (ValueError, TypeError) as exc:
                yield Rejection(ref, str(exc))
                continue
            if obs.type == "domain-name":
                yield Rejection(ref, "not an IP address")
                continue
            online = item.get("status") == "online"
            confidence = self.confidence if online else self.confidence * 0.6
            first_seen = parse_timestamp(item.get("first_seen")) or self.ctx.clock()
            indicator = build_indicator(
                obs,
                source=self.name,
                confidence=confidence,
                valid_from=first_seen,
                port=port,
                labels=["botnet-c2", str(item.get("status") or "")],
                description=f"Feodo Tracker C2 ({item.get('malware')}, {item.get('status')})",
            )
            yield from self._with_malware(indicator, item.get("malware"), [], confidence)
