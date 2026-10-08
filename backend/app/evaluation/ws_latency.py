"""Event-to-browser latency over a real Socket.IO connection (loopback).

Starts the actual app (uvicorn + the Socket.IO hub) on 127.0.0.1, connects a
python-socketio client over WebSocket, emits RISK_UPDATED events on the bus and
records, per event, the time from ``bus.emit`` to the client callback. Server and
client share one process, so both timestamps come from the same
``time.perf_counter`` clock (no clock skew). Measures the server-side path
(queue, 100 ms batching, serialization, the WebSocket hop); a browser adds its
own parse/render time on top.
"""

from __future__ import annotations

import socket
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.evaluation.harness import eval_settings

RISK = {"level": "low", "action": "monitor", "score": 1.0}


@dataclass
class WsSample:
    mode: str  # "steady" | "burst"
    index: int
    latency_ms: float


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def measure(steady: int = 300, rate_per_s: float = 50.0, burst: int = 2000) -> list[WsSample]:
    import socketio
    import uvicorn

    from app.main import create_app

    port = _free_port()
    with tempfile.TemporaryDirectory(prefix="dsn-ws-") as tmp:
        settings = eval_settings(Path(tmp) / "models").model_copy(
            update={
                "api_host": "127.0.0.1",
                "api_port": port,
                "iforest_autotrain": False,
                # The client's Origin; the hub enforces the same CORS allowlist as REST.
                "cors_origins": [f"http://127.0.0.1:{port}"],
            }
        )
        app = create_app(settings)
        server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
        )
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 60
        while not server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("uvicorn did not start")
            time.sleep(0.05)

        sent: dict[str, float] = {}
        got: dict[str, float] = {}
        done = threading.Event()
        expected = steady + burst
        client = socketio.Client(reconnection=False)

        @client.on("events")  # type: ignore[untyped-decorator,unused-ignore]
        def on_events(batch: list[dict[str, Any]]) -> None:
            now = time.perf_counter()
            for ev in batch:
                tag = str(ev.get("payload", {}).get("explanation", ""))
                if tag.startswith("probe:"):
                    got.setdefault(tag, now)
            if len(got) >= expected:
                done.set()

        client.connect(
            f"http://127.0.0.1:{port}",
            socketio_path="api/socket.io",
            transports=["websocket"],
            auth={"after_seq": 10**9},  # live only, no backlog replay
            wait_timeout=10,
        )
        bus = app.state.bus
        try:
            for i in range(steady):
                tag = f"probe:steady:{i}"
                sent[tag] = time.perf_counter()
                bus.emit("RISK_UPDATED", "dev-eval", explanation=tag, **RISK)
                time.sleep(1 / rate_per_s)
            time.sleep(0.5)
            for i in range(burst):
                tag = f"probe:burst:{i}"
                sent[tag] = time.perf_counter()
                bus.emit("RISK_UPDATED", "dev-eval", explanation=tag, **RISK)
            done.wait(30)
        finally:
            client.disconnect()
            server.should_exit = True
            thread.join(timeout=10)

    samples = []
    for tag, t_sent in sent.items():
        if tag in got:
            _, mode, index = tag.split(":")
            samples.append(WsSample(mode, int(index), (got[tag] - t_sent) * 1000))
    missing = len(sent) - len(samples)
    if missing:
        raise RuntimeError(f"{missing} of {len(sent)} events were not delivered")
    return samples
