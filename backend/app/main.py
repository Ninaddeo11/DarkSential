"""Application factory.

Run with ``uvicorn app.main:create_app --factory``. There is no module-level app
instance, so importing this module has no side effects and needs no secrets.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import devices, feeds, health, intel, risk
from app.core.config import Settings, get_settings
from app.core.events import EventBus
from app.core.health import CheckResult, HealthRegistry
from app.core.identifiers import DeviceIdHasher
from app.core.logging import configure_logging
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

    registry.register("database", database)
    registry.register("graph", graph)
    registry.register_static(
        "mqtt",
        "not_configured",
        "MQTT client arrives in Phase 4" if settings.mqtt_host else "DSN_MQTT_HOST unset",
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(
        settings.log_level, json_output=settings.log_json, secret_values=settings.secret_values()
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
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
        try:
            yield
        finally:
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

    app.include_router(health.router)
    app.include_router(feeds.router)
    app.include_router(intel.router)
    app.include_router(devices.router)
    app.include_router(risk.router)
    return app
