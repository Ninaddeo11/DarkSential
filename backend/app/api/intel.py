"""Read-only threat-intel queries over the STIX graph (lab deployments).

These endpoints don't change state. Mutating endpoints (manual feed runs,
quarantine) wait for authentication in Phase 6 (threat model O1/O7).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/intel", tags=["intel"])

MAX_EXTRACT_CHARS = 20_000


def _runtime(request: Request) -> Any:
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(503, "threat-intel graph is not available in hosted mode")
    return runtime


@router.get("/related-threats")
def related_threats(
    request: Request,
    ioc: str = Query(min_length=1, max_length=2048),
    max_hops: int = Query(default=3, ge=1, le=4),
) -> list[dict[str, Any]]:
    try:
        threats = _runtime(request).graph.related_threats(ioc, max_hops=max_hops)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return [t.model_dump() for t in threats]


@router.get("/cves")
def cves_for_cpe(
    request: Request, cpe: str = Query(min_length=8, max_length=512)
) -> list[dict[str, Any]]:
    try:
        matches = _runtime(request).graph.cves_for_cpe(cpe)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return [m.model_dump() for m in matches]


@router.get("/techniques")
def techniques_for_behavior(
    request: Request, rule_id: str = Query(min_length=1, max_length=128)
) -> list[dict[str, Any]]:
    return [t.model_dump() for t in _runtime(request).graph.techniques_for_behavior(rule_id)]


@router.get("/graph/counts")
def graph_counts(request: Request) -> dict[str, int]:
    counts: dict[str, int] = _runtime(request).graph.counts()
    return counts


class ExtractRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_EXTRACT_CHARS)


@router.post("/extract")
def extract_entities(request: Request, body: ExtractRequest) -> dict[str, Any]:
    """Run the NLP extractor on submitted text. Pure computation, no state change."""
    result = _runtime(request).runner.extractor().extract(body.text)
    data: dict[str, Any] = result.model_dump()
    return data
