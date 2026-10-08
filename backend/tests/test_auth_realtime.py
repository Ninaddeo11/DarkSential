from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core import auth
from app.core.auth import AuthError, issue_session, verify_token
from app.core.config import Settings
from app.core.events import EventBus
from app.core.ratelimit import RateLimiter, budget_for
from app.main import create_app
from tests.conftest import SettingsFactory

ADMIN = "admin-token-for-tests-0123456789abcdef"
VIEWER = "viewer-token-for-tests-0123456789abcd"
SECRET = "jwt-secret-for-tests-0123456789abcdef"
RISK: dict[str, Any] = {"score": 1.0, "level": "low", "action": "monitor", "explanation": "x"}


@pytest.fixture
def settings(make_settings: SettingsFactory) -> Settings:
    return make_settings(admin_token=ADMIN, viewer_token=VIEWER, auth_jwt_secret=SECRET)


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as c:
        yield c


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- sessions ---------------------------------------------------------------------


def test_login_grants_roles(client: TestClient) -> None:
    op = client.post("/api/auth/login", json={"secret": ADMIN}).json()
    view = client.post("/api/auth/login", json={"secret": VIEWER}).json()
    assert (op["role"], view["role"]) == ("operator", "viewer")
    assert client.post("/api/auth/login", json={"secret": "wrong"}).status_code == 401
    me = client.get("/api/auth/me", headers=bearer(view["access_token"])).json()
    assert me["role"] == "viewer"
    assert me["login_enabled"] is True
    # A viewer can read but not act.
    body = {"node_id": "dev-0000000000000000", "reason": "abc"}
    denied = client.post("/api/quarantines", json=body, headers=bearer(view["access_token"]))
    assert denied.status_code == 403
    allowed = client.post("/api/quarantines", json=body, headers=bearer(op["access_token"]))
    assert allowed.status_code == 404  # authorized; the device just doesn't exist


def test_expired_tampered_and_foreign_tokens_rejected(settings: Settings) -> None:
    old, _ = issue_session(settings, "operator", now=datetime.now(UTC) - timedelta(days=1))
    with pytest.raises(AuthError, match="ExpiredSignature"):
        verify_token(settings, old)
    good, _ = issue_session(settings, "viewer")
    head, payload, sig = good.split(".")
    flipped = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
    with pytest.raises(AuthError):
        verify_token(settings, f"{head}.{payload}.{flipped}")
    forged = jwt.encode(
        {"iss": "dsn", "aud": "dsn-dashboard", "sub": "x", "role": "operator", "iat": 0,
         "exp": int(time.time()) + 60},
        "a-different-secret-0123456789abcdefgh", algorithm="HS256",
    )  # fmt: skip
    with pytest.raises(AuthError):
        verify_token(settings, forged)
    none_alg = jwt.encode({"sub": "x"}, None, algorithm="none")  # type: ignore[arg-type]
    with pytest.raises(AuthError, match="unsupported"):
        verify_token(settings, none_alg)
    with pytest.raises(AuthError, match="malformed"):
        verify_token(settings, "not-a-jwt")


def test_reads_require_auth_in_production(make_settings: SettingsFactory) -> None:
    s = make_settings(
        env="production", cors_origins=["https://dsn.example"], admin_token=ADMIN,
        auth_jwt_secret=SECRET,
    )  # fmt: skip
    with TestClient(create_app(s)) as c:
        assert c.get("/api/devices").status_code == 401
        assert c.get("/api/health").status_code == 200  # probes stay open
        token = c.post("/api/auth/login", json={"secret": ADMIN}).json()["access_token"]
        assert c.get("/api/devices", headers=bearer(token)).status_code == 200


def test_auth_settings_validation(make_settings: SettingsFactory) -> None:
    with pytest.raises(ValidationError, match="go together"):
        make_settings(oidc_issuer="https://idp.example")
    with pytest.raises(ValidationError, match="https"):
        make_settings(
            oidc_issuer="https://idp.example", oidc_audience="dsn",
            oidc_jwks_url="http://idp.example/jwks",
        )  # fmt: skip
    with pytest.raises(ValidationError, match="auth_jwt_secret is required"):
        make_settings(admin_token=ADMIN)
    with pytest.raises(ValidationError, match="at least"):
        make_settings(auth_jwt_secret="short")


# --- OIDC -------------------------------------------------------------------------


@pytest.fixture
def oidc(make_settings: SettingsFactory, monkeypatch: pytest.MonkeyPatch) -> tuple[Settings, Any]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class FakeJwks:
        def get_signing_key_from_jwt(self, token: str) -> Any:
            assert jwt.get_unverified_header(token)["kid"] == "k1"
            return type("K", (), {"key": key.public_key()})()

    monkeypatch.setattr(auth, "_jwks_client", lambda url: FakeJwks())
    s = make_settings(
        oidc_issuer="https://idp.example", oidc_audience="dsn-api",
        oidc_jwks_url="https://idp.example/jwks",
    )  # fmt: skip
    return s, key


def _idp_token(key: Any, **claims: Any) -> str:
    base = {"iss": "https://idp.example", "aud": "dsn-api", "sub": "alice",
            "exp": int(time.time()) + 300}  # fmt: skip
    return jwt.encode(base | claims, key, algorithm="RS256", headers={"kid": "k1"})


def test_oidc_roles_and_claims(oidc: tuple[Settings, Any]) -> None:
    s, key = oidc
    operator = verify_token(s, _idp_token(key, roles=["dsn-operator"]))
    assert (operator.role, operator.source, operator.actor) == ("operator", "oidc", "oidc:alice")
    assert verify_token(s, _idp_token(key, roles="dsn-operator other")).role == "operator"
    assert verify_token(s, _idp_token(key)).role == "viewer"
    with pytest.raises(AuthError, match="InvalidAudience"):
        verify_token(s, _idp_token(key, aud="someone-else"))
    with pytest.raises(AuthError, match="InvalidIssuer"):
        verify_token(s, _idp_token(key, iss="https://evil.example"))
    with pytest.raises(AuthError, match="Expired"):
        verify_token(s, _idp_token(key, exp=int(time.time()) - 10))


# --- rate limits --------------------------------------------------------------------


def test_rate_limiter_refills() -> None:
    now = [0.0]
    rl = RateLimiter(clock=lambda: now[0])
    assert [rl.take("a", "login", 2) for _ in range(2)] == [0.0, 0.0]
    wait = rl.take("a", "login", 2)
    assert wait == pytest.approx(30.0)  # 2/min -> one token per 30 s
    assert rl.take("b", "login", 2) == 0.0  # per client
    now[0] = 30.0
    assert rl.take("a", "login", 2) == 0.0


def test_rate_limit_middleware(make_settings: SettingsFactory) -> None:
    s = make_settings(admin_token=ADMIN, auth_jwt_secret=SECRET, rate_limit_logins_per_minute=2)
    with TestClient(create_app(s)) as c:
        codes = [c.post("/api/auth/login", json={"secret": "x"}).status_code for _ in range(3)]
        assert codes == [401, 401, 429]
        limited = c.post("/api/auth/login", json={"secret": ADMIN})
        assert limited.status_code == 429
        assert int(limited.headers["Retry-After"]) >= 1
        assert all(c.get("/api/health").status_code == 200 for _ in range(5))  # exempt
    assert budget_for("GET", "/api/devices", s) == ("read", s.rate_limit_reads_per_minute)
    assert budget_for("POST", "/api/quarantines", s)[0] == "mutation"  # type: ignore[index]
    assert budget_for("GET", "/index.html", s) is None


# --- live events (Socket.IO) --------------------------------------------------------


def test_socketio_endpoint_is_mounted(client: TestClient) -> None:
    r = client.get("/api/socket.io/", params={"EIO": "4", "transport": "polling"})
    assert r.status_code == 200
    assert r.text.startswith("0{")  # engine.io "open" packet with the session id


class Recorder:
    def __init__(self) -> None:
        self.sent: list[tuple[str, Any, dict[str, Any]]] = []
        self.rooms: list[str] = []

    async def emit(self, event: str, data: Any = None, **kw: Any) -> None:
        self.sent.append((event, data, kw))

    async def enter_room(self, sid: str, room: str) -> None:
        self.rooms.append(room)


def _hub(settings: Settings, bus: EventBus) -> tuple[Any, Recorder]:
    from app.realtime import RealtimeHub

    hub = RealtimeHub(bus, settings)
    rec = Recorder()
    hub.sio.emit = rec.emit
    hub.sio.enter_room = rec.enter_room
    return hub, rec


def test_realtime_auth_replay_and_resync(settings: Settings) -> None:
    import socketio

    bus = EventBus(history=5)
    for _ in range(8):
        bus.emit("RISK_UPDATED", "dev-1", **RISK)
    held = [e.seq for e in bus.recent(limit=10)]
    hub, rec = _hub(settings, bus)
    token, _ = issue_session(settings, "viewer")
    asyncio.run(hub._connect("s1", {}, {"token": token, "after_seq": held[1]}))
    batches = [d for e, d, _ in rec.sent if e == "events"]
    assert [e["seq"] for e in batches[0]] == held[2:]  # resumed exactly after held[1]
    assert rec.rooms == ["live"]
    rec.sent.clear()
    asyncio.run(hub._connect("s2", {}, {"token": token, "after_seq": held[0] - 3}))
    assert rec.sent[0][0] == "resync"  # the gap is older than the buffer
    with pytest.raises(socketio.exceptions.ConnectionRefusedError):
        asyncio.run(hub._connect("s3", {}, {"token": "garbage"}))


def test_realtime_requires_token_when_reads_do(make_settings: SettingsFactory) -> None:
    import socketio

    s = make_settings(auth_reads=True, auth_jwt_secret=SECRET)
    hub, _ = _hub(s, EventBus())
    with pytest.raises(socketio.exceptions.ConnectionRefusedError):
        asyncio.run(hub._connect("s1", {}, None))
    open_hub, rec2 = _hub(make_settings(), EventBus())
    asyncio.run(open_hub._connect("s1", {}, None))  # dev default: anonymous reads
    assert rec2.rooms == ["live"]


def test_realtime_batches_bursts(settings: Settings) -> None:
    from app.realtime import MAX_BATCH

    bus = EventBus(history=10)
    hub, rec = _hub(settings, bus)
    for _ in range(MAX_BATCH + 250):
        bus.emit("RISK_UPDATED", "dev-1", **RISK)
    first = asyncio.run(hub.flush())
    second = asyncio.run(hub.flush())
    assert (first, second) == (MAX_BATCH, 250)
    sizes = [len(d) for e, d, kw in rec.sent if e == "events" and kw.get("room") == "live"]
    assert sizes == [MAX_BATCH, 250]  # two messages for 1250 events
    assert asyncio.run(hub.flush()) == 0
    asyncio.run(hub.stop())
    bus.emit("RISK_UPDATED", "dev-1", **RISK)
    assert asyncio.run(hub.flush()) == 0  # unsubscribed on stop
