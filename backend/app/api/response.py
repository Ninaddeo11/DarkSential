"""Quarantine control, device approval and the audit log.

Mutating endpoints require an **operator** bearer token (a session from
``POST /api/auth/login`` or an OIDC token with the operator role; see
``app.core.auth``). Bearer tokens aren't sent automatically by browsers, so
these endpoints aren't CSRF-able. With no auth configured, mutations are
disabled outright.
Every mutation is written to the hash-chained audit log.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.core.auth import OperatorAccess, Principal

router = APIRouter(prefix="/api", tags=["response"])


def _runtime(request: Request) -> Any:
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(503, "response control is not available in hosted mode")
    return runtime


class QuarantineRequest(BaseModel):
    node_id: str = Field(pattern=r"^dev-[0-9a-f]{16}$")
    reason: str = Field(min_length=3, max_length=500)
    minutes: int | None = Field(default=None, ge=1, le=7 * 24 * 60)


class ReleaseRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


@router.get("/quarantines")
def list_quarantines(
    request: Request,
    status_: Literal["active", "released", "failed"] | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = _runtime(request).response.list(status_, limit)
    return rows


@router.post("/quarantines", status_code=201)
def create_quarantine(
    request: Request, body: QuarantineRequest, who: Principal = OperatorAccess
) -> dict[str, Any]:
    from app.response.drivers import DriverError
    from app.response.service import QuarantineRefused

    rt = _runtime(request)
    try:
        row: dict[str, Any] = rt.response.quarantine(
            body.node_id,
            f"manual: {body.reason}",
            actor=who.actor,
            minutes=body.minutes,
            evidence={"manual": True},
        )
    except KeyError as exc:
        raise HTTPException(404, "unknown device") from exc
    except QuarantineRefused as exc:
        raise HTTPException(409, f"refused: {exc.reason}") from exc
    except DriverError as exc:
        raise HTTPException(502, "enforcement failed (see audit log)") from exc
    return row


@router.post("/quarantines/{quarantine_id}/release")
def release_quarantine(
    request: Request,
    quarantine_id: int,
    body: ReleaseRequest,
    who: Principal = OperatorAccess,
) -> dict[str, Any]:
    from app.response.drivers import DriverError

    rt = _runtime(request)
    try:
        row: dict[str, Any] = rt.response.release(
            quarantine_id, actor=who.actor, reason=f"manual: {body.reason}"
        )
    except KeyError as exc:
        raise HTTPException(404, "unknown quarantine") from exc
    except DriverError as exc:
        raise HTTPException(502, "release failed (see audit log)") from exc
    return row


@router.post("/devices/{node_id}/approve")
def approve_device(
    request: Request, node_id: str, who: Principal = OperatorAccess
) -> dict[str, Any]:
    rt = _runtime(request)
    try:
        view = rt.registry.approve(node_id)
    except KeyError as exc:
        raise HTTPException(404, "unknown device") from exc
    rt.audit.record(who.actor, "approve", node_id=node_id, details={"trust": "approved"})
    rt.risk.assess(node_id, trigger="approve")
    data: dict[str, Any] = view.model_dump()
    return data


@router.get("/audit")
def audit_log(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    node_id: str | None = Query(default=None, max_length=32),
    before_id: int | None = Query(default=None, ge=1),
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = _runtime(request).audit.entries(limit, node_id, before_id)
    return entries


@router.get("/audit/verify")
def verify_audit(request: Request) -> dict[str, Any]:
    result: dict[str, Any] = _runtime(request).audit.verify_chain().model_dump()
    return result
