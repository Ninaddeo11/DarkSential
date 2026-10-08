"""Dashboard/API authentication: short-lived JWT sessions and OIDC.

Two token sources, both resulting in a :class:`Principal` with a role:

* **Session JWTs** (HS256, ``DSN_AUTH_JWT_SECRET``). ``POST /api/auth/login``
  exchanges a long-lived secret for a short-lived token: ``DSN_ADMIN_TOKEN`` ->
  role ``operator``; the optional ``DSN_VIEWER_TOKEN`` -> role ``viewer``. The
  long-lived secret is sent once, not with every request.
* **OIDC access tokens** (RS256/ES256 from ``DSN_OIDC_ISSUER``), verified against
  the provider's JWKS (``DSN_OIDC_JWKS_URL``) with issuer and audience checks.
  ``DSN_OIDC_OPERATOR_ROLE`` in the ``DSN_OIDC_ROLES_CLAIM`` claim grants
  ``operator``; any other valid token is a ``viewer``.

Roles: ``viewer`` reads; ``operator`` reads and may quarantine / release / approve.
Reads require a token when ``reads_require_auth`` (default: production only).
Tokens are bearer tokens (never cookies), so the API isn't CSRF-able.
"""

from __future__ import annotations

import hmac
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any, Literal

import jwt
from fastapi import Depends, Header, HTTPException, Request, status

from app.core.config import Settings

log = logging.getLogger(__name__)

Role = Literal["viewer", "operator"]
ISSUER = "dsn"
AUDIENCE = "dsn-dashboard"
_ALGO = "HS256"
_OIDC_ALGOS = ["RS256", "ES256", "PS256"]


@dataclass(frozen=True)
class Principal:
    sub: str
    role: Role
    source: Literal["session", "oidc", "anonymous"]

    @property
    def actor(self) -> str:
        """Audit-log actor name."""
        if self.source == "session":
            return "api:admin" if self.role == "operator" else "api:viewer"
        return f"oidc:{self.sub}"[:64]

    def can(self, role: Role) -> bool:
        return role == "viewer" or self.role == "operator"


class AuthError(Exception):
    pass


def login_role(settings: Settings, secret: str) -> Role | None:
    """Which role a presented long-lived secret grants (constant-time compares)."""
    supplied = secret.encode()
    role: Role | None = None
    for candidate, granted in (
        (settings.admin_token, "operator"),
        (settings.viewer_token, "viewer"),
    ):
        if candidate is not None and hmac.compare_digest(
            supplied, candidate.get_secret_value().encode()
        ):
            role = role or granted  # type: ignore[assignment]
    return role


def issue_session(
    settings: Settings, role: Role, now: datetime | None = None
) -> tuple[str, datetime]:
    if settings.auth_jwt_secret is None:
        raise AuthError("sessions disabled: set DSN_AUTH_JWT_SECRET")
    now = now or datetime.now(UTC)
    expires = now + timedelta(minutes=settings.auth_session_minutes)
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "admin" if role == "operator" else "viewer",
        "role": role,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(claims, settings.auth_jwt_secret.get_secret_value(), algorithm=_ALGO)
    return token, expires


@lru_cache(maxsize=4)
def _jwks_client(url: str) -> Any:
    return jwt.PyJWKClient(url, cache_keys=True, lifespan=3600, timeout=5)


def verify_token(settings: Settings, token: str) -> Principal:
    """Verify a session JWT or an OIDC access token. Raises AuthError."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AuthError("malformed token") from exc
    alg = header.get("alg")
    if alg == _ALGO:
        if settings.auth_jwt_secret is None:
            raise AuthError("sessions disabled")
        try:
            claims = jwt.decode(
                token,
                settings.auth_jwt_secret.get_secret_value(),
                algorithms=[_ALGO],
                audience=AUDIENCE,
                issuer=ISSUER,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid session: {type(exc).__name__}") from exc
        role = claims.get("role")
        if role not in ("viewer", "operator"):
            raise AuthError("invalid role claim")
        return Principal(sub=str(claims["sub"]), role=role, source="session")
    if alg in _OIDC_ALGOS and settings.oidc_issuer:
        try:
            key = _jwks_client(str(settings.oidc_jwks_url)).get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=_OIDC_ALGOS,
                audience=settings.oidc_audience,
                issuer=settings.oidc_issuer,
                options={"require": ["exp", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid OIDC token: {type(exc).__name__}") from exc
        roles = claims.get(settings.oidc_roles_claim) or []
        if isinstance(roles, str):
            roles = roles.split()
        is_operator = isinstance(roles, list) and settings.oidc_operator_role in roles
        return Principal(
            sub=str(claims["sub"]), role="operator" if is_operator else "viewer", source="oidc"
        )
    raise AuthError("unsupported token")


def _bearer(authorization: str) -> str | None:
    scheme, _, value = authorization.partition(" ")
    return value.strip() if scheme.lower() == "bearer" and value.strip() else None


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"}
    )


def principal_from_header(settings: Settings, authorization: str) -> Principal | None:
    token = _bearer(authorization)
    if token is None:
        return None
    try:
        return verify_token(settings, token)
    except AuthError as exc:
        log.info("rejected token", extra={"reason": str(exc)})
        raise _unauthorized("invalid or expired token") from exc


def require_viewer(request: Request, authorization: str = Header(default="")) -> Principal:
    """Read access: a valid token, or anonymous when reads don't require auth."""
    settings: Settings = request.app.state.settings
    principal = principal_from_header(settings, authorization)
    if principal is not None:
        return principal
    if settings.reads_require_auth:
        raise _unauthorized("authentication required")
    return Principal(sub="anonymous", role="viewer", source="anonymous")


def require_operator(request: Request, authorization: str = Header(default="")) -> Principal:
    settings: Settings = request.app.state.settings
    if not settings.auth_enabled:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "mutating API disabled: configure DSN_AUTH_JWT_SECRET + DSN_ADMIN_TOKEN, or OIDC",
        )
    principal = principal_from_header(settings, authorization)
    if principal is None:
        raise _unauthorized("authentication required")
    if not principal.can("operator"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "operator role required")
    return principal


ReadAccess = Depends(require_viewer)
OperatorAccess = Depends(require_operator)
