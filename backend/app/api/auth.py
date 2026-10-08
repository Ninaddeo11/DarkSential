"""Login (session JWTs) and "who am I"."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.auth import AuthError, Principal, ReadAccess, issue_session, login_role

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    secret: str = Field(min_length=1, max_length=512)


class Session(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    role: Literal["viewer", "operator"]
    expires_at: str


class Me(BaseModel):
    sub: str
    role: Literal["viewer", "operator"]
    source: str
    reads_require_auth: bool
    login_enabled: bool
    oidc_issuer: str | None


@router.post("/login", response_model=Session)
def login(request: Request, body: LoginRequest) -> Session:
    settings = request.app.state.settings
    role = login_role(settings, body.secret)
    if role is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    try:
        token, expires = issue_session(settings, role)
    except AuthError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    return Session(access_token=token, role=role, expires_at=expires.isoformat())


@router.get("/me", response_model=Me)
def me(request: Request, principal: Principal = ReadAccess) -> Me:
    settings = request.app.state.settings
    return Me(
        sub=principal.sub,
        role=principal.role,
        source=principal.source,
        reads_require_auth=settings.reads_require_auth,
        login_enabled=settings.auth_jwt_secret is not None,
        oidc_issuer=settings.oidc_issuer,
    )
