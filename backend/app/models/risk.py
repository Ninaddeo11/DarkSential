"""Persisted risk decisions (one row per assessment; full explanation kept)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, UTCDateTime


class RiskDecisionRow(Base):
    __tablename__ = "risk_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[str] = mapped_column(String(32), index=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    score: Mapped[float] = mapped_column(Float)
    level: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(32))
    contributions: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    factors: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    explanation: Mapped[str] = mapped_column(Text)
    evidence_paths: Mapped[list[Any]] = mapped_column(JSON)
    ml: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    trigger: Mapped[str] = mapped_column(String(32))

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_id": self.node_id,
            "ts": self.ts,
            "score": self.score,
            "level": self.level,
            "action": self.action,
            "contributions": self.contributions,
            "factors": self.factors,
            "explanation": self.explanation,
            "evidence_paths": self.evidence_paths,
            "ml": self.ml,
            "trigger": self.trigger,
        }
