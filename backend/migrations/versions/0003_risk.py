"""Phase 3 schema: risk decisions.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from app.core.db import UTCDateTime

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "risk_decisions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("node_id", sa.String(32), nullable=False),
        sa.Column("ts", UTCDateTime(), nullable=False),
        sa.Column("score", sa.Float, nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("contributions", sa.JSON, nullable=False),
        sa.Column("factors", sa.JSON, nullable=False),
        sa.Column("explanation", sa.Text, nullable=False),
        sa.Column("evidence_paths", sa.JSON, nullable=False),
        sa.Column("ml", sa.JSON, nullable=True),
        sa.Column("trigger", sa.String(32), nullable=False),
    )
    op.create_index("ix_risk_decisions_node_id", "risk_decisions", ["node_id"])
    op.create_index("ix_risk_decisions_ts", "risk_decisions", ["ts"])


def downgrade() -> None:
    op.drop_table("risk_decisions")
