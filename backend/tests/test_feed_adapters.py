from __future__ import annotations

import json
import random
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx2
import pytest

from app.core.config import Settings
from app.feeds.abusech import FeodoAdapter, ThreatFoxAdapter, UrlhausAdapter
from app.feeds.attack import MitreAttackAdapter
from app.feeds.base import AdapterContext, FeedAdapter, MockAdapter, Rejection
from app.feeds.config import load_feeds_config
from app.feeds.http import HttpFetcher, RateLimiter, RetryPolicy
from app.feeds.kev import CisaKevAdapter
from app.feeds.nvd import NvdCveAdapter
from app.feeds.registry import FeedUnavailableError, build_adapter
from app.intel.nlp import EntityExtractor
from app.intel.stix import stix_id
from tests.conftest import FIXTURES, SettingsFactory, requires_spacy

NOW = datetime(2026, 10, 2, 12, tzinfo=UTC)


def no_extractor() -> EntityExtractor:
    raise AssertionError("extractor not expected for this feed")


def offline(settings: Settings, name: str) -> FeedAdapter:
    cfg = load_feeds_config(settings.feeds_config_path).feeds[name]
    return build_adapter(settings, cfg, no_extractor, clock=lambda: NOW)


def objects_of(adapter: FeedAdapter) -> tuple[list[dict[str, Any]], list[str]]:
    result = adapter.normalize_to_stix(adapter.fetch())
    return result.objects, [f"{r.ref}: {r.reason}" for r in result.rejected]


def by_type(objects: list[dict[str, Any]]) -> Counter[str]:
    return Counter(o["type"] for o in objects)


# --- offline (MockAdapter) normalization ------------------------------------------------


def test_kev_fixture(settings: Settings) -> None:
    adapter = offline(settings, "cisa_kev")
    assert isinstance(adapter, MockAdapter)
    objs, rejected = objects_of(adapter)
    assert rejected == []
    assert by_type(objs) == {"vulnerability": 5}
    goahead = next(o for o in objs if o["name"] == "CVE-2017-17562")  # virtual lab cam-yard
    assert goahead["x_dsn_kev"]["date_added"] == "2021-12-10"
    tplink = next(o for o in objs if o["name"] == "CVE-2023-1389")
    assert tplink["id"] == stix_id("vulnerability", "CVE-2023-1389")
    assert tplink["x_dsn_kev"]["date_added"] == "2023-05-01"
    assert tplink["created"].startswith("2023-05-01")


def test_nvd_fixture(settings: Settings) -> None:
    objs, rejected = objects_of(offline(settings, "nvd_cve"))
    assert rejected == []
    names = {o["name"] for o in objs}
    assert names == {
        "CVE-2023-1389",
        "CVE-2021-36260",
        "CVE-2017-17215",
        "CVE-2014-8361",
        "CVE-2021-44228",
        "CVE-2017-17562",
    }
    goahead = next(o for o in objs if o["name"] == "CVE-2017-17562")
    match = goahead["x_dsn_cpe_matches"][0]
    assert match["criteria"].startswith("cpe:2.3:a:embedthis:goahead:*")
    assert match["version_end_excluding"] == "3.6.5"
    log4j = next(o for o in objs if o["name"] == "CVE-2021-44228")
    assert log4j["x_dsn_cvss"]["base_score"] == 10.0
    assert log4j["x_dsn_kev"]["date_added"]  # NVD carries CISA KEV fields too
    huawei = next(o for o in objs if o["name"] == "CVE-2017-17215")
    assert "x_dsn_kev" not in huawei
    assert huawei["x_dsn_cpe_matches"][0]["criteria"].startswith("cpe:2.3:o:huawei:hg532")


def test_attack_fixture_filters_revoked_and_strips_refs(settings: Settings) -> None:
    objs, rejected = objects_of(offline(settings, "mitre_attack"))
    assert rejected == []
    raw = json.loads((FIXTURES / "attack/attack.sample.json").read_text(encoding="utf-8"))
    revoked = [o["id"] for o in raw["objects"] if o.get("revoked")]
    live_patterns = [
        o for o in raw["objects"] if o["type"] == "attack-pattern" and not o.get("revoked")
    ]
    counts = by_type(objs)
    assert counts["attack-pattern"] == len(live_patterns) > 10
    assert counts["intrusion-set"] == 2
    assert counts["relationship"] > 30
    assert "identity" not in counts
    assert "marking-definition" not in counts
    assert all("created_by_ref" not in o for o in objs)
    assert revoked
    assert not {o["id"] for o in objs} & set(revoked)


def test_feodo_fixture(settings: Settings) -> None:
    objs, rejected = objects_of(offline(settings, "feodo"))
    assert rejected == []
    indicators = [o for o in objs if o["type"] == "indicator"]
    assert len(indicators) == 5
    emotet = next(o for o in objs if o["type"] == "malware" and o["name"] == "Emotet")
    rels = [o for o in objs if o["type"] == "relationship" and o["target_ref"] == emotet["id"]]
    assert rels
    assert rels[0]["relationship_type"] == "indicates"
    offline_ind = next(o for o in indicators if "162.243.103.246" in o["pattern"])
    assert "network-traffic:dst_port = 8080" in offline_ind["pattern"]
    assert offline_ind["confidence"] == 48  # offline C2: 80 * 0.6


def test_urlhaus_fixture(settings: Settings) -> None:
    objs, rejected = objects_of(offline(settings, "urlhaus"))
    assert rejected == []
    patterns = sorted(o["pattern"] for o in objs)
    assert "[ipv4-addr:value = '192.0.2.45']" in patterns
    assert "[domain-name:value = 'update-cdn.example.net']" in patterns
    quoted = next(p for p in patterns if "x.sh" in p)
    assert "b=\\'quoted\\'" in quoted  # escaped, still a valid pattern


def test_threatfox_fixture(settings: Settings) -> None:
    objs, rejected = objects_of(offline(settings, "threatfox"))
    assert any("unsupported ioc_type" in r for r in rejected)
    counts = by_type(objs)
    assert counts["indicator"] == 5
    malware = {o["name"] for o in objs if o["type"] == "malware"}
    assert malware == {"QakBot", "Mirai"}  # "Unknown malware" not materialized
    qakbot = next(o for o in objs if o["type"] == "malware" and o["name"] == "QakBot")
    assert "Qbot" in qakbot["aliases"]
    ipport = next(o for o in objs if o["type"] == "indicator" and "203.0.113.10" in o["pattern"])
    assert "dst_port = 443" in ipport["pattern"]
    assert ipport["confidence"] == 52  # 70 * 0.75


@requires_spacy
def test_darkweb_fixture(settings: Settings) -> None:
    cfg = load_feeds_config(settings.feeds_config_path).feeds["darkweb"]
    adapter = build_adapter(settings, cfg, EntityExtractor, clock=lambda: NOW)
    objs, rejected = objects_of(adapter)
    assert any("empty text" in r for r in rejected)
    reports = {o["name"]: o for o in objs if o["type"] == "report"}
    assert len(reports) == 6
    first = next(r for n, r in reports.items() if "dw-0001" in n)
    assert first["x_dsn_technique_ids"] == ["T1105", "T1190"]
    vuln_id = stix_id("vulnerability", "CVE-2023-1389")
    assert vuln_id in first["object_refs"]
    adversarial = next(r for n, r in reports.items() if "dw-0005" in n)
    entity_values = {e["value"] for e in adversarial["x_dsn_entities"]}
    assert {"CVE-2014-8361", "CVE-2021-44228"} <= entity_values
    assert "<script>" in adversarial["description"]  # kept as inert text, escaped at display
    assert "\x1b" not in adversarial["description"]
    noisy = next(r for n, r in reports.items() if "dw-0004" in n)
    assert noisy["object_refs"] == [stix_id("identity", "intel-source:chat-relay")]
    undated = next(r for n, r in reports.items() if "dw-0006" in n)
    assert undated["published"].startswith("2026-10-02")  # fell back to fetch time
    assert all(o["confidence"] <= 40 for o in objs if "confidence" in o)


def test_darkweb_bad_items_path(make_settings: SettingsFactory) -> None:
    from app.feeds.darkweb import GenericRestDarkWebAdapter, Mention

    s = make_settings(darkweb_items_path="results.items")
    cfg = load_feeds_config(s.feeds_config_path).feeds["darkweb"]
    adapter = GenericRestDarkWebAdapter(AdapterContext(s, cfg, None), no_extractor)
    mentions = list(adapter.mentions({"data": []}))
    assert len(mentions) == 1
    assert isinstance(mentions[0], Rejection)
    assert "not a list" in mentions[0].reason
    nested = list(
        GenericRestDarkWebAdapter(
            AdapterContext(
                make_settings(
                    darkweb_items_path="results.items",
                    darkweb_field_map={"id": "meta.uid", "text": "body", "source": "src"},
                ),
                cfg,
                None,
            ),
            no_extractor,
        ).mentions({"results": {"items": [{"meta": {"uid": 7}, "body": "hi"}, {"body": 1}]}})
    )
    first, second = nested
    assert isinstance(first, Mention)
    assert first.id == "7"
    assert first.source == "unknown-source"
    assert isinstance(second, Rejection)
    assert "missing id or text" in second.reason


# --- registry -----------------------------------------------------------------------


def test_missing_credentials_in_live_mode(make_settings: SettingsFactory) -> None:
    s = make_settings(offline_mode=False)
    cfg = load_feeds_config(s.feeds_config_path).feeds["urlhaus"]
    with pytest.raises(FeedUnavailableError, match="requires abusech_auth_key"):
        build_adapter(s, cfg, no_extractor)


def test_disabled_feed(settings: Settings) -> None:
    cfg = load_feeds_config(settings.feeds_config_path).feeds["feodo"]
    with pytest.raises(FeedUnavailableError, match="disabled"):
        build_adapter(settings, cfg.model_copy(update={"enabled": False}), no_extractor)


def test_fixture_path_traversal_blocked(settings: Settings) -> None:
    cfg = load_feeds_config(settings.feeds_config_path).feeds["feodo"]
    evil = cfg.model_copy(update={"fixture": "../backend/config/feeds.yaml"})
    with pytest.raises(FeedUnavailableError, match="escapes"):
        build_adapter(settings, evil, no_extractor)
    with pytest.raises(FeedUnavailableError, match="no fixture"):
        build_adapter(settings, cfg.model_copy(update={"fixture": None}), no_extractor)


def test_live_adapter_has_fetcher(make_settings: SettingsFactory) -> None:
    s = make_settings(offline_mode=False)
    cfg = load_feeds_config(s.feeds_config_path).feeds["cisa_kev"]
    adapter = build_adapter(s, cfg, no_extractor)
    assert isinstance(adapter, CisaKevAdapter)
    assert adapter.ctx.fetcher is not None
    assert adapter.ctx.fetcher.client.follow_redirects is False
    adapter.ctx.fetcher.client.close()


def test_mock_adapter_has_no_fetcher(settings: Settings) -> None:
    adapter = offline(settings, "cisa_kev")
    with pytest.raises(RuntimeError, match="no HTTP fetcher"):
        adapter.inner._fetcher()  # type: ignore[attr-defined]


# --- live fetch() against a mock transport -------------------------------------------------


Handler = Callable[[httpx2.Request], httpx2.Response]


def live(
    cls: type[FeedAdapter], settings: Settings, name: str, handler: Handler, tmp_path: Path
) -> FeedAdapter:
    cfg = load_feeds_config(settings.feeds_config_path).feeds[name]
    fetcher = HttpFetcher(
        client=httpx2.Client(transport=httpx2.MockTransport(handler)),
        limiter=RateLimiter(1000, 1),
        cache=None,
        cache_ttl_seconds=0,
        max_response_bytes=10_000_000,
        retry=RetryPolicy(max_attempts=1),
        rng=random.Random(0),
    )
    return cls(AdapterContext(settings, cfg, fetcher, lambda: NOW))


def fixture_json(rel: str) -> Any:
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


def test_live_kev_fetch(settings: Settings, tmp_path: Path) -> None:
    def handler(req: httpx2.Request) -> httpx2.Response:
        assert req.url.host == "www.cisa.gov"
        return httpx2.Response(200, json=fixture_json("kev/kev.sample.json"))

    adapter = live(CisaKevAdapter, settings, "cisa_kev", handler, tmp_path)
    assert len(adapter.normalize_to_stix(adapter.fetch()).objects) == 5


def test_live_nvd_paginates_with_api_key(make_settings: SettingsFactory, tmp_path: Path) -> None:
    s = make_settings(nvd_api_key="nvd-test-key")
    page = fixture_json("nvd/nvd.sample.json")
    vulns = page["vulnerabilities"]
    requests: list[httpx2.Request] = []

    def handler(req: httpx2.Request) -> httpx2.Response:
        requests.append(req)
        start = int(req.url.params["startIndex"])
        chunk = vulns[start : start + 2]
        return httpx2.Response(200, json={"totalResults": len(vulns), "vulnerabilities": chunk})

    adapter = live(NvdCveAdapter, s, "nvd_cve", handler, tmp_path)
    raw = adapter.fetch()
    assert len(raw["vulnerabilities"]) == 6
    assert [r.url.params["startIndex"] for r in requests] == ["0", "2", "4"]
    assert all(r.headers["apiKey"] == "nvd-test-key" for r in requests)
    params = requests[0].url.params
    assert params["lastModEndDate"] == "2026-10-02T12:00:00.000+00:00"
    assert params["lastModStartDate"] == "2026-09-30T12:00:00.000+00:00"


def test_nvd_rejects_rejected_and_undated(settings: Settings) -> None:
    adapter = offline(settings, "nvd_cve")
    raw = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2020-1111", "vulnStatus": "Rejected"}},
            {"cve": {"id": "CVE-2020-2222"}},
            {"cve": {"id": "BAD", "published": "2020-01-01T00:00:00"}},
        ]
    }
    result = adapter.normalize_to_stix(raw)
    assert result.objects == []
    reasons = [r.reason for r in result.rejected]
    assert reasons[0] == "rejected by NVD"
    assert reasons[1] == "missing published date"
    assert "invalid CVE" in reasons[2]


def test_live_attack_rejects_unknown_domain(settings: Settings, tmp_path: Path) -> None:
    hits: list[str] = []

    def handler(req: httpx2.Request) -> httpx2.Response:
        hits.append(req.url.path)
        return httpx2.Response(200, json={"type": "bundle", "id": "bundle--x", "objects": []})

    adapter = live(MitreAttackAdapter, settings, "mitre_attack", handler, tmp_path)
    assert adapter.fetch() == [{"type": "bundle", "id": "bundle--x", "objects": []}] * 2
    assert hits[0].endswith("/enterprise-attack/enterprise-attack.json")
    bad = adapter.ctx.config.model_copy(update={"options": {"domains": ["../../evil"]}})
    adapter.ctx.config = bad
    with pytest.raises(ValueError, match="unknown ATT&CK domain"):
        adapter.fetch()


def test_live_abusech_sends_auth_key(make_settings: SettingsFactory, tmp_path: Path) -> None:
    s = make_settings(abusech_auth_key="abuse-key-123")
    seen: list[httpx2.Request] = []

    def handler(req: httpx2.Request) -> httpx2.Response:
        seen.append(req)
        if req.url.host.startswith("threatfox"):
            assert json.loads(req.content) == {"query": "get_iocs", "days": 1}
            return httpx2.Response(200, json=fixture_json("threatfox/get_iocs.sample.json"))
        return httpx2.Response(200, json=fixture_json("urlhaus/urls_recent.sample.json"))

    for cls, name in ((UrlhausAdapter, "urlhaus"), (ThreatFoxAdapter, "threatfox")):
        adapter = live(cls, s, name, handler, tmp_path)
        assert adapter.normalize_to_stix(adapter.fetch()).objects
    assert all(r.headers["Auth-Key"] == "abuse-key-123" for r in seen)
    assert seen[1].method == "POST"


def test_abusech_requires_key_for_fetch(settings: Settings, tmp_path: Path) -> None:
    adapter = live(UrlhausAdapter, settings, "urlhaus", lambda r: httpx2.Response(500), tmp_path)
    with pytest.raises(RuntimeError, match="DSN_ABUSECH_AUTH_KEY"):
        adapter.fetch()


def test_abusech_bad_query_status(settings: Settings) -> None:
    for name, payload in (("urlhaus", {"query_status": "error"}), ("threatfox", {})):
        result = offline(settings, name).normalize_to_stix(payload)
        assert result.objects == []
        assert "query_status" in result.rejected[0].reason
    feodo = offline(settings, "feodo").normalize_to_stix({"not": "a list"})
    assert "expected a JSON list" in feodo.rejected[0].reason
    garbage = offline(settings, "feodo").normalize_to_stix(
        [{"ip_address": "not-ip", "port": 1}, {"ip_address": "evil.example.com", "port": 1}]
    )
    assert [r.reason for r in garbage.rejected][1] == "not an IP address"


def test_live_feodo_no_auth_needed(settings: Settings, tmp_path: Path) -> None:
    def handler(req: httpx2.Request) -> httpx2.Response:
        assert "Auth-Key" not in req.headers
        return httpx2.Response(200, json=fixture_json("feodo/ipblocklist.sample.json"))

    adapter = live(FeodoAdapter, settings, "feodo", handler, tmp_path)
    assert len(adapter.fetch()) == 5


def test_live_darkweb_auth_header(make_settings: SettingsFactory, tmp_path: Path) -> None:
    from app.feeds.darkweb import GenericRestDarkWebAdapter

    s = make_settings(
        offline_mode=False,
        darkweb_api_url="https://intel.example.com/v1/mentions",
        darkweb_api_key="dw-secret",
        darkweb_auth_header="X-Api-Key",
        darkweb_auth_scheme="",
    )
    cfg = load_feeds_config(s.feeds_config_path).feeds["darkweb"]
    seen: list[httpx2.Request] = []

    def handler(req: httpx2.Request) -> httpx2.Response:
        seen.append(req)
        return httpx2.Response(200, json={"data": []})

    fetcher = HttpFetcher(
        client=httpx2.Client(transport=httpx2.MockTransport(handler)),
        limiter=RateLimiter(10, 1),
        cache=None,
        cache_ttl_seconds=0,
        max_response_bytes=1000,
    )
    adapter = GenericRestDarkWebAdapter(AdapterContext(s, cfg, fetcher), no_extractor)
    assert adapter.fetch() == {"data": []}
    assert seen[0].headers["X-Api-Key"] == "dw-secret"
    no_url = GenericRestDarkWebAdapter(AdapterContext(make_settings(), cfg, fetcher), no_extractor)
    with pytest.raises(RuntimeError, match="DSN_DARKWEB_API_URL"):
        no_url.fetch()
