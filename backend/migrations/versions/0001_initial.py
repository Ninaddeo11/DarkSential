"""Phase 1 schema: feed run history.

Revision ID: 0001
Revises:
Create Date: 2026-10-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from app.core.db import UTCDateTime

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "feed_runs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("feed", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", UTCDateTime(), nullable=False),
        sa.Column("finished_at", UTCDateTime(), nullable=False),
        sa.Column("objects", sa.Integer, nullable=False),
        sa.Column("rejected", sa.Integer, nullable=False),
        sa.Column("nodes", sa.Integer, nullable=False),
        sa.Column("edges", sa.Integer, nullable=False),
        sa.Column("skipped_edges", sa.Integer, nullable=False),
        sa.Column("error", sa.Text, nullable=True),
    )
    op.create_index("ix_feed_runs_feed", "feed_runs", ["feed"])
    op.create_index("ix_feed_runs_started_at", "feed_runs", ["started_at"])


def downgrade() -> None:
    op.drop_table("feed_runs")
