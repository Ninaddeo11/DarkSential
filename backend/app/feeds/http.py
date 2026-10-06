"""Resilient HTTP fetching for feed adapters.

- ``RateLimiter``: thread-safe token bucket (client-side politeness).
- ``RetryPolicy``: exponential backoff with *full jitter*; honors Retry-After.
- ``ResponseCache``: on-disk cache with TTL plus ETag / Last-Modified revalidation.
- ``HttpFetcher``: ties them together and caps response size (streams the body
  and aborts past the limit, so a hostile or broken feed cannot exhaust memory).

Clocks, sleep and RNG are injectable so all of this is tested deterministically.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx2

log = logging.getLogger(__name__)

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

Clock = Callable[[], float]
Sleep = Callable[[float], None]


class FeedHTTPError(RuntimeError):
    """Non-retryable HTTP failure, or retries exhausted."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ResponseTooLargeError(FeedHTTPError):
    pass


def _safe_url(url: str) -> str:
    """URL without query string, for logs and errors (queries may carry keys)."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


class RateLimiter:
    """Token bucket: ``capacity`` tokens, refilled at ``capacity / per_seconds``."""

    def __init__(
        self,
        requests: int,
        per_seconds: float,
        *,
        clock: Clock = time.monotonic,
        sleep: Sleep = time.sleep,
    ) -> None:
        if requests < 1 or per_seconds <= 0:
            raise ValueError("invalid rate limit")
        self._capacity = float(requests)
        self._rate = requests / per_seconds
        self._tokens = float(requests)
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
        self._updated = now

    def acquire(self) -> float:
        """Block until a token is available. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return waited
                wait = (1 - self._tokens) / self._rate
            self._sleep(wait)
            waited += wait


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_seconds: float = 1.0
    cap_seconds: float = 60.0

    def backoff(self, attempt: int, rng: random.Random) -> float:
        """Full jitter: uniform(0, min(cap, base * 2**attempt)), attempt starting at 0."""
        ceiling = min(self.cap_seconds, self.base_seconds * (2**attempt))
        return rng.uniform(0, ceiling)


def _retry_after_seconds(value: str | None, now: float) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        return max(0.0, parsedate_to_datetime(value).timestamp() - now)
    except (TypeError, ValueError):
        return None


@dataclass
class CacheEntry:
    body: bytes
    fetched_at: float
    etag: str | None = None
    last_modified: str | None = None


class ResponseCache:
    """Filesystem cache keyed by sha256(method, url, params, body)."""

    def __init__(self, directory: Path) -> None:
        self._dir = directory

    @staticmethod
    def key(method: str, url: str, params: Mapping[str, Any] | None, body: Any) -> str:
        material = json.dumps(
            [method.upper(), url, sorted((params or {}).items()), body], default=str
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _paths(self, key: str) -> tuple[Path, Path]:
        return self._dir / f"{key}.json", self._dir / f"{key}.body"

    def get(self, key: str) -> CacheEntry | None:
        meta_path, body_path = self._paths(key)
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            return CacheEntry(
                body=body_path.read_bytes(),
                fetched_at=float(meta["fetched_at"]),
                etag=meta.get("etag"),
                last_modified=meta.get("last_modified"),
            )
        except (OSError, ValueError, KeyError):
            return None

    def put(self, key: str, entry: CacheEntry) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        meta_path, body_path = self._paths(key)
        tmp = body_path.with_suffix(".tmp")
        tmp.write_bytes(entry.body)
        tmp.replace(body_path)
        meta = {
            "fetched_at": entry.fetched_at,
            "etag": entry.etag,
            "last_modified": entry.last_modified,
        }
        meta_path.write_text(json.dumps(meta), encoding="utf-8")


@dataclass
class HttpFetcher:
    client: httpx2.Client
    limiter: RateLimiter
    cache: ResponseCache | None
    cache_ttl_seconds: float
    max_response_bytes: int
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    rng: random.Random = field(default_factory=random.Random)
    clock: Clock = time.time
    sleep: Sleep = time.sleep

    def fetch_json(
        self,
        url: str,
        *,
        method: str = "GET",
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        json_body: Any = None,
    ) -> Any:
        body = self.fetch_bytes(
            url, method=method, params=params, headers=headers, json_body=json_body
        )
        try:
            return json.loads(body)
        except ValueError as exc:
            raise FeedHTTPError(f"invalid JSON from {_safe_url(url)}") from exc

    def fetch_bytes(
        self,
        url: str,
        *,
        method: str = "GET",
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        json_body: Any = None,
    ) -> bytes:
        key = ResponseCache.key(method, url, params, json_body)
        cached = self.cache.get(key) if self.cache else None
        if cached and self.clock() - cached.fetched_at < self.cache_ttl_seconds:
            log.debug("cache hit", extra={"url": _safe_url(url)})
            return cached.body

        request_headers = dict(headers or {})
        if cached and cached.etag:
            request_headers["If-None-Match"] = cached.etag
        if cached and cached.last_modified:
            request_headers["If-Modified-Since"] = cached.last_modified

        for attempt in range(self.retry.max_attempts):
            self.limiter.acquire()
            try:
                status, resp_headers, payload = self._send(
                    method, url, params, request_headers, json_body
                )
            except httpx2.TransportError as exc:
                if attempt + 1 >= self.retry.max_attempts:
                    raise FeedHTTPError(
                        f"{type(exc).__name__} for {_safe_url(url)} after {attempt + 1} attempts"
                    ) from exc
                self._backoff(attempt, None, url, type(exc).__name__)
                continue

            if status == 304 and cached:
                cached.fetched_at = self.clock()
                if self.cache:
                    self.cache.put(key, cached)
                return cached.body
            if 200 <= status < 300:
                if self.cache:
                    self.cache.put(
                        key,
                        CacheEntry(
                            body=payload,
                            fetched_at=self.clock(),
                            etag=resp_headers.get("etag"),
                            last_modified=resp_headers.get("last-modified"),
                        ),
                    )
                return payload
            if status in RETRY_STATUSES and attempt + 1 < self.retry.max_attempts:
                self._backoff(attempt, resp_headers.get("retry-after"), url, str(status))
                continue
            raise FeedHTTPError(f"HTTP {status} from {_safe_url(url)}", status=status)
        raise FeedHTTPError(f"retries exhausted for {_safe_url(url)}")  # pragma: no cover

    def _backoff(self, attempt: int, retry_after: str | None, url: str, reason: str) -> None:
        delay = self.retry.backoff(attempt, self.rng)
        hinted = _retry_after_seconds(retry_after, self.clock())
        if hinted is not None:
            delay = min(max(delay, hinted), self.retry.cap_seconds)
        log.warning(
            "feed request retry",
            extra={"url": _safe_url(url), "reason": reason, "attempt": attempt + 1, "delay": delay},
        )
        self.sleep(delay)

    def _send(
        self,
        method: str,
        url: str,
        params: Mapping[str, Any] | None,
        headers: Mapping[str, str],
        json_body: Any,
    ) -> tuple[int, httpx2.Headers, bytes]:
        with self.client.stream(
            method, url, params=dict(params or {}), headers=dict(headers), json=json_body
        ) as resp:
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > self.max_response_bytes:
                raise ResponseTooLargeError(
                    f"{_safe_url(url)} declares {declared} bytes > limit", status=resp.status_code
                )
            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > self.max_response_bytes:
                    raise ResponseTooLargeError(
                        f"{_safe_url(url)} exceeded {self.max_response_bytes} bytes",
                        status=resp.status_code,
                    )
                chunks.append(chunk)
            return resp.status_code, resp.headers, b"".join(chunks)
