"""Risk decisions (read-only): current scores, per-device history, model description."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/api/risk", tags=["risk"])


def _runtime(request: Request) -> Any:
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(503, "risk engine is not available in hosted mode")
    return runtime


@router.get("")
def current_risk(request: Request) -> list[dict[str, Any]]:
    """Latest decision per device, highest score first."""
    latest: list[dict[str, Any]] = _runtime(request).risk.latest_all()
    return latest


@router.get("/model")
def risk_model(request: Request) -> dict[str, Any]:
    """The transparent scorer's configuration and the ML comparison model's metadata."""
    rt = _runtime(request)
    cfg = rt.risk.cfg
    ml = rt.risk.ml
    return {
        "linear": {
            "weights": cfg.weights,
            "thresholds": cfg.thresholds,
            "actions": cfg.actions,
            "formula": "score = sum(weight_f * value_f * 100), value_f in [0, 1]",
        },
        "ml": None
        if ml is None
        else {
            "model": "xgboost",
            "role": "comparison only; decisions use the linear scorer",
            **{k: v for k, v in ml.meta.items() if k != "hmac_sha256"},
        },
    }


@router.get("/{node_id}")
def device_risk(
    request: Request, node_id: str, limit: int = Query(default=20, ge=1, le=200)
) -> dict[str, Any]:
    rt = _runtime(request)
    if not node_id.startswith("dev-") or len(node_id) > 32 or rt.registry.get(node_id) is None:
        raise HTTPException(404, "unknown device")
    history = rt.risk.history(node_id, limit)
    return {"node_id": node_id, "latest": history[0] if history else None, "history": history}
