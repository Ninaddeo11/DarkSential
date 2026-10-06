"""Builds the right adapter (live or mock) for a feed."""

from __future__ import annotations

from collections.abc import Callable

import httpx2

from app.core.config import Settings
from app.feeds.abusech import FeodoAdapter, ThreatFoxAdapter, UrlhausAdapter
from app.feeds.attack import MitreAttackAdapter
from app.feeds.base import AdapterContext, Clock, FeedAdapter, MockAdapter, utcnow
from app.feeds.config import FeedConfig
from app.feeds.darkweb import GenericRestDarkWebAdapter
from app.feeds.http import HttpFetcher, RateLimiter, ResponseCache
from app.feeds.kev import CisaKevAdapter
from app.feeds.nvd import NvdCveAdapter
from app.feeds.status import feed_mode
from app.intel.nlp import EntityExtractor

ExtractorFactory = Callable[[], EntityExtractor]

_SIMPLE: dict[str, type[FeedAdapter]] = {
    "cisa_kev": CisaKevAdapter,
    "nvd_cve": NvdCveAdapter,
    "mitre_attack": MitreAttackAdapter,
    "urlhaus": UrlhausAdapter,
    "threatfox": ThreatFoxAdapter,
    "feodo": FeodoAdapter,
}

# Defaults matching fixtures/darkweb/mentions.sample.json, so offline mode works
# whatever field map is configured for the real provider.
_DARKWEB_FIXTURE_SETTINGS = {
    "darkweb_items_path": "data",
    "darkweb_field_map": {
        "id": "id",
        "source": "source",
        "published": "published_at",
        "text": "text",
    },
}


class FeedUnavailableError(RuntimeError):
    pass


def _make_fetcher(settings: Settings, cfg: FeedConfig) -> HttpFetcher:
    rate = cfg.rate_limit
    if cfg.name == "nvd_cve" and settings.nvd_api_key and cfg.rate_limit_with_key:
        rate = cfg.rate_limit_with_key
    client = httpx2.Client(
        timeout=cfg.timeout_seconds,
        headers={"User-Agent": settings.http_user_agent, "Accept": "application/json"},
        # Don't follow redirects: custom auth headers (Auth-Key, apiKey) would be
        # replayed to whatever host a redirect points at.
        follow_redirects=False,
    )
    return HttpFetcher(
        client=client,
        limiter=RateLimiter(rate.requests, rate.per_seconds),
        cache=ResponseCache(settings.cache_dir / cfg.name),
        cache_ttl_seconds=cfg.cache_ttl_seconds,
        max_response_bytes=cfg.max_response_bytes,
    )


def build_adapter(
    settings: Settings,
    cfg: FeedConfig,
    extractor_factory: ExtractorFactory,
    clock: Clock = utcnow,
) -> FeedAdapter:
    mode = feed_mode(settings, cfg)
    if mode in {"disabled", "missing_credentials"}:
        detail = f"requires {cfg.requires}" if mode == "missing_credentials" else "disabled"
        raise FeedUnavailableError(f"{cfg.name}: {detail}")

    offline = mode == "mock"
    if cfg.name == "darkweb":
        adapter_settings = (
            settings.model_copy(update=_DARKWEB_FIXTURE_SETTINGS) if offline else settings
        )
        ctx = AdapterContext(
            adapter_settings, cfg, None if offline else _make_fetcher(settings, cfg), clock
        )
        inner: FeedAdapter = GenericRestDarkWebAdapter(ctx, extractor_factory)
    else:
        ctx = AdapterContext(
            settings, cfg, None if offline else _make_fetcher(settings, cfg), clock
        )
        inner = _SIMPLE[cfg.name](ctx)

    if not offline:
        return inner
    if not cfg.fixture:
        raise FeedUnavailableError(f"{cfg.name}: offline mode but no fixture configured")
    fixture = (settings.fixtures_dir / cfg.fixture).resolve()
    if settings.fixtures_dir.resolve() not in fixture.parents:
        raise FeedUnavailableError(f"{cfg.name}: fixture path escapes fixtures dir")
    return MockAdapter(inner, fixture)
