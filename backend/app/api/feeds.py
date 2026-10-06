"""Feed status endpoint (read-only)."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.feeds.status import FeedStatusResponse, static_status

router = APIRouter(prefix="/api/feeds", tags=["feeds"])


@router.get("/status", response_model=FeedStatusResponse)
def feeds_status(request: Request) -> FeedStatusResponse:
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        return static_status(request.app.state.settings, request.app.state.feeds)
    status: FeedStatusResponse = runtime.feed_status()
    return status
