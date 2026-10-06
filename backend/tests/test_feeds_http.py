from __future__ import annotations

import json
import random
from collections.abc import Callable
from pathlib import Path

import httpx2
import pytest

from app.feeds.http import (
    FeedHTTPError,
    HttpFetcher,
    RateLimiter,
    ResponseCache,
    ResponseTooLargeError,
    RetryPolicy,
    _retry_after_seconds,
    _safe_url,
)


class FakeClock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


Handler = Callable[[httpx2.Request], httpx2.Response]


def make_fetcher(
    handler: Handler,
    tmp_path: Path,
    *,
    clock: FakeClock | None = None,
    cache: bool = True,
    max_bytes: int = 1_000_000,
    attempts: int = 4,
) -> tuple[HttpFetcher, FakeClock]:
    clock = clock or FakeClock()
    fetcher = HttpFetcher(
        client=httpx2.Client(transport=httpx2.MockTransport(handler)),
        limiter=RateLimiter(100, 1, clock=clock, sleep=clock.sleep),
        cache=ResponseCache(tmp_path) if cache else None,
        cache_ttl_seconds=60,
        max_response_bytes=max_bytes,
        retry=RetryPolicy(max_attempts=attempts, base_seconds=1, cap_seconds=30),
        rng=random.Random(7),
        clock=clock,
        sleep=clock.sleep,
    )
    return fetcher, clock


# --- RateLimiter -------------------------------------------------------------------------


def test_rate_limiter_allows_burst_then_waits() -> None:
    clock = FakeClock(0)
    limiter = RateLimiter(2, 10, clock=clock, sleep=clock.sleep)
    assert limiter.acquire() == 0
    assert limiter.acquire() == 0
    waited = limiter.acquire()  # bucket empty: refill rate 0.2 tokens/s -> 5 s
    assert waited == pytest.approx(5.0)
    assert clock.now == pytest.approx(5.0)


def test_rate_limiter_refills_over_time() -> None:
    clock = FakeClock(0)
    limiter = RateLimiter(1, 1, clock=clock, sleep=clock.sleep)
    limiter.acquire()
    clock.now += 1.0
    assert limiter.acquire() == 0


@pytest.mark.parametrize(("requests", "per"), [(0, 1), (1, 0)])
def test_rate_limiter_rejects_invalid(requests: int, per: float) -> None:
    with pytest.raises(ValueError, match="invalid rate limit"):
        RateLimiter(requests, per)


# --- RetryPolicy ---------------------------------------------------------------------------


def test_backoff_full_jitter_bounds() -> None:
    policy = RetryPolicy(max_attempts=10, base_seconds=1, cap_seconds=8)
    rng = random.Random(1)
    for attempt in range(10):
        ceiling = min(8, 2**attempt)
        for _ in range(50):
            assert 0 <= policy.backoff(attempt, rng) <= ceiling


def test_retry_after_parsing() -> None:
    assert _retry_after_seconds("7", 0) == 7
    assert _retry_after_seconds(None, 0) is None
    assert _retry_after_seconds("garbage", 0) is None
    # HTTP-date 10 s in the future relative to `now`.
    assert _retry_after_seconds("Thu, 01 Jan 1970 00:00:20 GMT", 10) == pytest.approx(10)


def test_safe_url_drops_query() -> None:
    assert _safe_url("https://h/p?apiKey=secret") == "https://h/p"


# --- HttpFetcher ---------------------------------------------------------------------------


def test_fetch_json_and_cache_hit(tmp_path: Path) -> None:
    calls: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json={"ok": True}, headers={"ETag": '"v1"'})

    fetcher, _ = make_fetcher(handler, tmp_path)
    assert fetcher.fetch_json("https://feed.test/x", params={"a": 1}) == {"ok": True}
    assert fetcher.fetch_json("https://feed.test/x", params={"a": 1}) == {"ok": True}
    assert len(calls) == 1  # second served from cache
    assert calls[0].url.params["a"] == "1"


def test_conditional_revalidation_304(tmp_path: Path) -> None:
    calls: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        if request.headers.get("If-None-Match") == '"v1"':
            return httpx2.Response(304)
        return httpx2.Response(
            200, content=b'{"n": 1}', headers={"ETag": '"v1"', "Last-Modified": "x"}
        )

    fetcher, clock = make_fetcher(handler, tmp_path)
    assert fetcher.fetch_json("https://feed.test/x") == {"n": 1}
    clock.now += 120  # cache stale -> revalidate
    assert fetcher.fetch_json("https://feed.test/x") == {"n": 1}
    assert calls[1].headers["If-None-Match"] == '"v1"'
    assert calls[1].headers["If-Modified-Since"] == "x"
    assert len(calls) == 2


def test_retries_503_honoring_retry_after(tmp_path: Path) -> None:
    responses = [
        httpx2.Response(503, headers={"Retry-After": "12"}),
        httpx2.Response(429),
        httpx2.Response(200, json=[1]),
    ]

    def handler(request: httpx2.Request) -> httpx2.Response:
        return responses.pop(0)

    fetcher, clock = make_fetcher(handler, tmp_path, cache=False)
    assert fetcher.fetch_json("https://feed.test/x") == [1]
    assert clock.sleeps[0] >= 12  # Retry-After respected
    assert len(clock.sleeps) == 2


def test_non_retryable_status_raises(tmp_path: Path) -> None:
    fetcher, clock = make_fetcher(lambda r: httpx2.Response(401), tmp_path, cache=False)
    with pytest.raises(FeedHTTPError) as err:
        fetcher.fetch_json("https://feed.test/x?apiKey=s3cret")
    assert err.value.status == 401
    assert "s3cret" not in str(err.value)
    assert clock.sleeps == []


def test_retries_exhausted_on_5xx(tmp_path: Path) -> None:
    fetcher, clock = make_fetcher(lambda r: httpx2.Response(500), tmp_path, cache=False)
    with pytest.raises(FeedHTTPError, match="HTTP 500"):
        fetcher.fetch_json("https://feed.test/x")
    assert len(clock.sleeps) == 3  # 4 attempts, 3 backoffs


def test_transport_errors_retry_then_fail(tmp_path: Path) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("boom", request=request)

    fetcher, clock = make_fetcher(handler, tmp_path, cache=False, attempts=3)
    with pytest.raises(FeedHTTPError, match=r"ConnectError .* after 3 attempts"):
        fetcher.fetch_json("https://feed.test/x")
    assert len(clock.sleeps) == 2


def test_transport_error_then_success(tmp_path: Path) -> None:
    state = {"n": 0}

    def handler(request: httpx2.Request) -> httpx2.Response:
        state["n"] += 1
        if state["n"] == 1:
            raise httpx2.ReadTimeout("slow", request=request)
        return httpx2.Response(200, json={"ok": 1})

    fetcher, _ = make_fetcher(handler, tmp_path, cache=False)
    assert fetcher.fetch_json("https://feed.test/x") == {"ok": 1}


def test_response_size_cap_declared(tmp_path: Path) -> None:
    fetcher, _ = make_fetcher(
        lambda r: httpx2.Response(200, content=b"x" * 100, headers={"Content-Length": "100"}),
        tmp_path,
        max_bytes=10,
    )
    with pytest.raises(ResponseTooLargeError):
        fetcher.fetch_bytes("https://feed.test/big")


def test_response_size_cap_streamed(tmp_path: Path) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, content=iter([b"a" * 8, b"b" * 8]))  # no content-length

    fetcher, _ = make_fetcher(handler, tmp_path, max_bytes=10)
    with pytest.raises(ResponseTooLargeError, match="exceeded"):
        fetcher.fetch_bytes("https://feed.test/big")


def test_invalid_json(tmp_path: Path) -> None:
    fetcher, _ = make_fetcher(lambda r: httpx2.Response(200, content=b"<html>"), tmp_path)
    with pytest.raises(FeedHTTPError, match="invalid JSON"):
        fetcher.fetch_json("https://feed.test/x")


def test_post_json_body_and_cache_key(tmp_path: Path) -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(json.loads(request.content))
        return httpx2.Response(200, json={"query_status": "ok"})

    fetcher, _ = make_fetcher(handler, tmp_path)
    fetcher.fetch_json("https://feed.test/api", method="POST", json_body={"days": 1})
    fetcher.fetch_json("https://feed.test/api", method="POST", json_body={"days": 2})
    assert seen == [{"days": 1}, {"days": 2}]  # different bodies, different cache keys


def test_cache_tolerates_corruption(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    key = ResponseCache.key("GET", "u", None, None)
    (tmp_path / f"{key}.json").write_text("{not json", encoding="utf-8")
    assert cache.get(key) is None
