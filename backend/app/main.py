"""Application factory.

Run with ``uvicorn app.main:create_app --factory``. There is no module-level app
instance, so importing this module has no side effects and needs no secrets.
In lab mode the live event stream (Socket.IO) is mounted at /api/socket.io.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api import auth, devices, feeds, health, intel, response, risk
from app.core.auth import ReadAccess
from app.core.config import Settings, get_settings
from app.core.events import EventBus
from app.core.health import CheckResult, HealthRegistry
from app.core.identifiers import DeviceIdHasher
from app.core.logging import configure_logging
from app.core.ratelimit import RateLimiter, budget_for, retry_after_header
from app.feeds.config import load_feeds_config

log = logging.getLogger(__name__)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _register_health_checks(app: FastAPI, settings: Settings) -> None:
    registry: HealthRegistry = app.state.health
    mode = "dry-run" if settings.dry_run else "ENFORCING"
    registry.register_static(
        "config", "ok", f"enforcement={mode}, deployment={settings.deployment}"
    )

    async def database() -> CheckResult:
        runtime = getattr(app.state, "runtime", None)
        if runtime is None:
            return CheckResult(status="not_configured", detail="no database in hosted mode")
        result: CheckResult = await runtime.check_database()
        return result

    async def graph() -> CheckResult:
        runtime = getattr(app.state, "runtime", None)
        if runtime is None:
            return CheckResult(status="not_configured", detail="no graph in hosted mode")
        result: CheckResult = await runtime.check_graph()
        return result

    async def response() -> CheckResult:
        runtime = getattr(app.state, "runtime", None)
        if runtime is None:
            return CheckResult(status="not_configured", detail="no enforcement in hosted mode")
        result: CheckResult = await runtime.check_response()
        return result

    async def mqtt() -> CheckResult:
        runtime = getattr(app.state, "runtime", None)
        if runtime is None:
            return CheckResult(status="not_configured", detail="no MQTT in hosted mode")
        result: CheckResult = await runtime.check_mqtt()
        return result

    registry.register("database", database)
    registry.register("graph", graph)
    registry.register("response", response)
    registry.register("mqtt", mqtt)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(
        settings.log_level, json_output=settings.log_json, secret_values=settings.secret_values()
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        log.info(
            "startup",
            extra={
                "version": __version__,
                "env": settings.env,
                "dry_run": settings.dry_run,
                "offline_mode": settings.offline_mode,
                "lab_cidr": str(settings.lab_cidr),
            },
        )
        if not settings.dry_run:
            log.warning("DRY_RUN is disabled: enforcing actions will modify the lab network")
        runtime = None
        if settings.deployment == "lab":
            from app.runtime import LabRuntime  # lab extra, imported lazily

            runtime = LabRuntime.build(settings, app.state.feeds, bus=app.state.bus)
            runtime.start()
            app.state.runtime = runtime
        hub = getattr(app.state, "realtime", None)
        if hub is not None:
            hub.start()
        try:
            yield
        finally:
            if hub is not None:
                await hub.stop()
            if runtime is not None:
                runtime.stop()
                app.state.runtime = None
            log.info("shutdown")

    is_prod = settings.env == "production"
    app = FastAPI(
        title="Darknet Sentinel Nexus",
        version=__version__,
        lifespan=lifespan,
        docs_url=None if is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if is_prod else "/openapi.json",
    )
    app.state.settings = settings
    app.state.device_ids = DeviceIdHasher(
        settings.device_id_hmac_key.get_secret_value().encode("utf-8")
    )
    app.state.feeds = load_feeds_config(settings.feeds_config_path)
    app.state.bus = EventBus()
    app.state.runtime = None
    app.state.health = HealthRegistry()
    _register_health_checks(app, settings)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Accept a caller-supplied request ID only if it is a well-formed UUID.
        supplied = request.headers.get("X-Request-ID", "")
        try:
            request_id = str(uuid.UUID(supplied))
        except ValueError:
            request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers.update(_SECURITY_HEADERS)
        return response

    limiter = RateLimiter()
    app.state.rate_limiter = limiter

    @app.middleware("http")
    async def rate_limit(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        budget = budget_for(request.method, request.url.path, settings)
        if settings.rate_limit_enabled and budget is not None:
            wait = limiter.take(_client_address(request, settings), *budget)
            if wait > 0:
                return JSONResponse(
                    {"detail": "rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": retry_after_header(wait), **_SECURITY_HEADERS},
                )
        return await call_next(request)

    app.include_router(health.router)
    app.include_router(auth.router)
    # Reads need a viewer token when DSN_AUTH_READS (default: production only).
    for router in (feeds.router, intel.router, devices.router, risk.router, response.router):
        app.include_router(router, dependencies=[ReadAccess])
    _mount_realtime(app, settings)
    return app


def _client_address(request: Request, settings: Settings) -> str:
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded:
            return forwarded[:64]
    return request.client.host if request.client else "unknown"


def _mount_realtime(app: FastAPI, settings: Settings) -> None:
    """Live events over Socket.IO (lab only: serverless can't hold sockets)."""
    app.state.realtime = None
    if settings.deployment != "lab":
        return
    try:
        from app.realtime import SOCKET_PATH, RealtimeHub
    except ImportError:  # python-socketio is in the `lab` extra
        log.warning("python-socketio not installed: live events disabled")
        return
    hub = RealtimeHub(app.state.bus, settings)
    app.state.realtime = hub
    app.mount("/" + SOCKET_PATH, hub.asgi_app(None))
