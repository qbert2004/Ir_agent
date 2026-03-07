"""Initial schema: events, incidents, iocs

Revision ID: 0001
Revises:
Create Date: 2025-03-04 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── incidents ─────────────────────────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.Column("host", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("classification", sa.String(256), nullable=True),
        sa.Column("threat_score", sa.Float(), nullable=True),
        sa.Column("assessment_json", sa.Text(), nullable=True),
        sa.Column("timeline_json", sa.Text(), nullable=True),
        sa.Column("mitre_techniques_json", sa.Text(), nullable=True),
        sa.Column("key_findings_json", sa.Text(), nullable=True),
        sa.Column("recommendations_json", sa.Text(), nullable=True),
        sa.Column("affected_hosts_json", sa.Text(), nullable=True),
        sa.Column("affected_users_json", sa.Text(), nullable=True),
        sa.Column("root_cause", sa.Text(), nullable=True),
        sa.Column("impact_assessment", sa.Text(), nullable=True),
    )
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])
    op.create_index("ix_incidents_host", "incidents", ["host"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_threat_score", "incidents", ["threat_score"])

    # ── events ────────────────────────────────────────────────────────────────
    op.create_table(
        "events",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("timestamp", sa.String(64), nullable=True),
        sa.Column("event_id", sa.String(16), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=True),
        sa.Column("hostname", sa.String(128), nullable=True),
        sa.Column("user", sa.String(128), nullable=True),
        sa.Column("channel", sa.String(64), nullable=True),
        sa.Column("process_name", sa.String(256), nullable=True),
        sa.Column("process_id", sa.Integer(), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("parent_process", sa.String(256), nullable=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("destination_ip", sa.String(64), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("script_block_text", sa.Text(), nullable=True),
        sa.Column("ml_confidence", sa.Float(), nullable=True),
        sa.Column("ml_label", sa.String(32), nullable=True),
        sa.Column("ml_reason", sa.String(512), nullable=True),
        sa.Column("processing_path", sa.String(16), nullable=True),
        sa.Column("threat_score", sa.Float(), nullable=True),
        sa.Column("threat_severity", sa.String(16), nullable=True),
        sa.Column("assessment_json", sa.Text(), nullable=True),
        sa.Column(
            "incident_id",
            sa.String(32),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_events_received_at", "events", ["received_at"])
    op.create_index("ix_events_event_id", "events", ["event_id"])
    op.create_index("ix_events_hostname", "events", ["hostname"])
    op.create_index("ix_events_threat_score", "events", ["threat_score"])
    op.create_index("ix_events_threat_severity", "events", ["threat_severity"])
    op.create_index("ix_events_incident", "events", ["incident_id"])
    op.create_index("ix_events_hostname_ts", "events", ["hostname", "timestamp"])

    # ── iocs ──────────────────────────────────────────────────────────────────
    op.create_table(
        "iocs",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(32),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("ioc_type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("context", sa.String(256), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("is_malicious", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("vt_score", sa.String(16), nullable=True),
        sa.Column("abuse_score", sa.Integer(), nullable=True),
        sa.Column("ti_tags", sa.String(512), nullable=True),
        sa.Column("ti_checked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_iocs_incident_id", "iocs", ["incident_id"])
    op.create_index("ix_iocs_ioc_type", "iocs", ["ioc_type"])
    op.create_index("ix_iocs_value", "iocs", ["value"])
    op.create_index("ix_iocs_type_value", "iocs", ["ioc_type", "value"])


def downgrade() -> None:
    op.drop_table("iocs")
    op.drop_table("events")
    op.drop_table("incidents")
