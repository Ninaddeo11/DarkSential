"""Phase 2 schema: devices, detections, behavior baselines.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from app.core.db import UTCDateTime

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("node_id", sa.String(32), nullable=False),
        sa.Column("identity_hmac", sa.String(64), nullable=False),
        sa.Column("identity_kind", sa.String(16), nullable=False),
        sa.Column("oui", sa.String(8), nullable=True),
        sa.Column("vendor", sa.String(128), nullable=True),
        sa.Column("randomized_mac", sa.Boolean, nullable=False),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("trust", sa.String(16), nullable=False),
        sa.Column("services", sa.JSON, nullable=False),
        sa.Column("cpes", sa.JSON, nullable=False),
        sa.Column("sources", sa.JSON, nullable=False),
        sa.Column("attributes", sa.JSON, nullable=False),
        sa.Column("first_seen", UTCDateTime(), nullable=False),
        sa.Column("last_seen", UTCDateTime(), nullable=False),
    )
    op.create_index("ix_devices_node_id", "devices", ["node_id"], unique=True)
    op.create_index("ix_devices_identity_hmac", "devices", ["identity_hmac"], unique=True)
    op.create_index("ix_devices_ip", "devices", ["ip"])
    op.create_index("ix_devices_last_seen", "devices", ["last_seen"])

    op.create_table(
        "detections",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("node_id", sa.String(32), nullable=False),
        sa.Column("ts", UTCDateTime(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("score", sa.Float, nullable=False),
        sa.Column("techniques", sa.JSON, nullable=False),
        sa.Column("evidence", sa.JSON, nullable=False),
        sa.Column("window_start", UTCDateTime(), nullable=False),
        sa.Column("window_end", UTCDateTime(), nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
    )
    op.create_index("ix_detections_node_id", "detections", ["node_id"])
    op.create_index("ix_detections_ts", "detections", ["ts"])

    op.create_table(
        "device_baselines",
        sa.Column("node_id", sa.String(32), primary_key=True),
        sa.Column("state", sa.JSON, nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("device_baselines")
    op.drop_table("detections")
    op.drop_table("devices")
