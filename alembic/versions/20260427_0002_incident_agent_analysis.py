"""Add agent_analysis_json and incident_summary to incidents table

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-27 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("agent_analysis_json", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("incident_summary", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("incidents", "incident_summary")
    op.drop_column("incidents", "agent_analysis_json")
