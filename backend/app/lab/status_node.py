"""Virtual status node: verifies signed commands and tracks the indicator state.

Same contract as ``app.mqtt.commands`` (signer). A command is accepted only if:

1. every signed field matches ``[A-Za-z0-9._:-]`` and the command is known,
2. the HMAC-SHA256 signature verifies (constant-time compare),
3. ``|now - ts| <= ttl`` with ttl clamped to 1..300 s (stale otherwise),
4. its id was not accepted before (replay; the last 256 ids are remembered).

Only accepted ids are remembered, so a forged message can't poison the cache.
The node's state (NORMAL / ALERT / QUARANTINED) is what a physical node would
show on an LED; here it is published in telemetry and shown in the dashboard.
"""

from __future__ import annotations

import json
from collections import deque
from typing import Any, Literal

from app.mqtt.commands import verify

Verdict = Literal["ok", "bad_json", "bad_field", "bad_cmd", "bad_sig", "stale", "replay"]
State = Literal["NORMAL", "ALERT", "QUARANTINED"]

COMMANDS = frozenset({"QUARANTINE", "ALERT", "RECOVER", "NORMAL"})
MAX_TTL = 300
REPLAY_MEMORY = 256
MAX_PAYLOAD = 1024


def next_state(cmd: str, current: State) -> State:
    if cmd == "QUARANTINE":
        return "QUARANTINED"
    if cmd == "ALERT":  # an alert never hides an active quarantine indication
        return current if current == "QUARANTINED" else "ALERT"
    if cmd in ("RECOVER", "NORMAL"):
        return "NORMAL"
    return current


class StatusNodeLogic:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("command key must be at least 32 bytes")
        self._key = key
        self._seen: deque[str] = deque(maxlen=REPLAY_MEMORY)
        self.state: State = "NORMAL"
        self.last_node: str = ""

    def handle(self, raw: bytes, now: int) -> tuple[str, Verdict]:
        """Returns (command id or "", verdict); updates state on success."""
        if len(raw) > MAX_PAYLOAD:
            return "", "bad_json"
        try:
            cmd: Any = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return "", "bad_json"
        if not isinstance(cmd, dict):
            return "", "bad_json"
        if not isinstance(cmd.get("ts"), int) or not isinstance(cmd.get("ttl"), int):
            return "", "bad_field"
        cid = cmd.get("id")
        if not isinstance(cid, str) or not cid or not isinstance(cmd.get("sig"), str):
            return "", "bad_field"
        if cmd.get("cmd") not in COMMANDS:
            return cid, "bad_cmd"
        if not verify(cmd, self._key):  # also rejects unsafe characters
            return cid, "bad_sig"
        ttl = min(max(int(cmd["ttl"]), 1), MAX_TTL)
        if abs(now - int(cmd["ts"])) > ttl:
            return cid, "stale"
        if cid in self._seen:
            return cid, "replay"
        self._seen.append(cid)
        self.state = next_state(str(cmd["cmd"]), self.state)
        self.last_node = str(cmd.get("node_id") or "")
        return cid, "ok"
