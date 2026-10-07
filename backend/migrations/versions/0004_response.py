"""Phase 4 schema: quarantines and the hash-chained audit log.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from app.core.db import UTCDateTime

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "quarantines",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("node_id", sa.String(32), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("evidence", sa.JSON, nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("driver", sa.String(16), nullable=False),
        sa.Column("dry_run", sa.Boolean, nullable=False),
        sa.Column("started_at", UTCDateTime(), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column("released_at", UTCDateTime(), nullable=True),
        sa.Column("released_by", sa.String(64), nullable=True),
        sa.Column("release_reason", sa.Text, nullable=True),
    )
    op.create_index("ix_quarantines_node_id", "quarantines", ["node_id"])
    op.create_index("ix_quarantines_status", "quarantines", ["status"])
    op.create_index("ix_quarantines_expires_at", "quarantines", ["expires_at"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("ts", UTCDateTime(), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("node_id", sa.String(32), nullable=True),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("details", sa.JSON, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False, unique=True),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_node_id", "audit_log", ["node_id"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("quarantines")
