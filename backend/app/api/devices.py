"""Devices, detections, events and discovery capabilities (read-only).

Approval and other state changes stay CLI-only until API auth lands (Phase 6).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/api", tags=["devices"])


def _runtime(request: Request) -> Any:
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(503, "devices are not available in hosted mode")
    return runtime


def _detections(runtime: Any, node_id: str | None, limit: int) -> list[dict[str, Any]]:
    from sqlalchemy import select  # lab extra, lazy

    from app.models.device import Detection

    with runtime.sessions() as session:
        query = select(Detection).order_by(Detection.ts.desc(), Detection.id.desc()).limit(limit)
        if node_id:
            query = query.where(Detection.node_id == node_id)
        return [
            {
                "id": d.id,
                "node_id": d.node_id,
                "ts": d.ts,
                "kind": d.kind,
                "rule_id": d.rule_id,
                "severity": d.severity,
                "score": d.score,
                "techniques": d.techniques,
                "summary": d.summary,
                "evidence": d.evidence,
            }
            for d in session.scalars(query)
        ]


@router.get("/devices")
def list_devices(request: Request) -> list[dict[str, Any]]:
    return [d.model_dump() for d in _runtime(request).registry.list()]


@router.get("/devices/{node_id}")
def get_device(request: Request, node_id: str) -> dict[str, Any]:
    rt = _runtime(request)
    if not node_id.startswith("dev-") or len(node_id) > 32:
        raise HTTPException(404, "unknown device")
    device = rt.registry.get(node_id)
    if device is None:
        raise HTTPException(404, "unknown device")
    latest = rt.pipeline.latest.get(node_id)
    baseline = rt.pipeline.baseline(node_id)
    return {
        "device": device.model_dump(),
        "baseline": {
            "windows": baseline.windows,
            "mature": baseline.windows >= rt.behavior_cfg.baseline.min_windows,
            "protocols": sorted(baseline.protocols),
        },
        "latest_window": latest.model_dump() if latest else None,
        "detections": _detections(rt, node_id, 20),
    }


@router.get("/detections")
def list_detections(
    request: Request,
    node_id: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    return _detections(_runtime(request), node_id, limit)


@router.get("/events")
def recent_events(
    request: Request,
    after_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    node_id: str | None = Query(default=None, max_length=32),
) -> list[dict[str, Any]]:
    bus = request.app.state.bus
    return [e.model_dump() for e in bus.recent(limit=limit, node_id=node_id, after_seq=after_seq)]


@router.get("/discovery/capabilities")
def discovery_capabilities(request: Request) -> dict[str, Any]:
    from app.detect import capabilities

    return {k: v.model_dump() for k, v in capabilities.report(request.app.state.settings).items()}


@router.get("/rules")
def list_rules(request: Request) -> list[dict[str, Any]]:
    rt = _runtime(request)
    return [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity,
            "techniques": r.techniques,
            "rationale": r.rationale,
            "source": r.source,
            "linked": [t.external_id for t in rt.graph.techniques_for_behavior(r.id)],
        }
        for r in rt.rules.rules
    ]
