"""The real-time event contract, shared by backend and frontend.

One payload model per event type. ``EventBus.emit`` validates every payload
against it (unknown keys are rejected), so the wire format can't drift from what
the dashboard expects. ``scripts/gen_event_types.py`` turns these models into
``frontend/src/generated/events.ts``; CI fails if that file is stale.

Wire envelope (Socket.IO ``events`` message, and ``GET /api/events``)::

    {"seq": 42, "type": "RISK_UPDATED", "ts": "<ISO-8601>", "node_id": "dev-…",
     "payload": {…}}
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class _Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")


RiskLevel = Literal["low", "medium", "high", "critical"]


class Contribution(_Payload):
    factor: str
    value: float
    weight: float
    contribution: float


class DeviceConnected(_Payload):
    returning: bool
    trust: str
    vendor: str | None = None
    ip: str | None = None
    source: str


class CpeGuess(_Payload):
    cpe: str
    confidence: float
    basis: str
    service: str


class DeviceProfiled(_Payload):
    vendor: str | None = None
    hostname: str | None = None
    services: list[str] = []
    cpes: list[CpeGuess] = []


class AnomalyDetected(_Payload):
    kind: Literal["anomaly", "rule"]
    summary: str
    window_end: str | None = None
    score: float | None = None
    cold_start: bool | None = None
    rule_id: str | None = None
    severity: str | None = None
    techniques: list[str] = []


class ThreatCorrelated(_Payload):
    summary: str
    value: float
    evidence: list[dict[str, Any]] = []


class RiskUpdated(_Payload):
    score: float
    level: RiskLevel
    action: str
    explanation: str
    previous_score: float | None = None
    contributions: list[Contribution] = []


class QuarantineStarted(_Payload):
    ip: str | None = None
    reason: str
    minutes: int
    actor: str
    dry_run: bool


class QuarantineCompleted(_Payload):
    ok: bool
    quarantine_id: int | None = None
    ip: str | None = None
    expires_at: str | None = None
    dry_run: bool | None = None
    refused: str | None = None
    error: str | None = None
    command_id: str | None = None  # signed status-node command sent


class RecoveryStarted(_Payload):
    quarantine_id: int
    actor: str
    reason: str


class DeviceRestored(_Payload):
    quarantine_id: int
    ip: str | None = None


PAYLOADS: dict[str, type[_Payload]] = {
    "DEVICE_CONNECTED": DeviceConnected,
    "DEVICE_PROFILED": DeviceProfiled,
    "ANOMALY_DETECTED": AnomalyDetected,
    "THREAT_CORRELATED": ThreatCorrelated,
    "RISK_UPDATED": RiskUpdated,
    "QUARANTINE_STARTED": QuarantineStarted,
    "QUARANTINE_COMPLETED": QuarantineCompleted,
    "RECOVERY_STARTED": RecoveryStarted,
    "DEVICE_RESTORED": DeviceRestored,
}


def validate_payload(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize (JSON-safe, defaults filled) an event payload."""
    model = PAYLOADS[event_type]
    return model.model_validate(payload).model_dump(mode="json")
