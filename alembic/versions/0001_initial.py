from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def _json_type():
    return postgresql.JSONB().with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "nodes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("expected_vpn_ip", sa.String(length=120), nullable=False),
        sa.Column("minion_api_url", sa.String(length=500), nullable=True),
        sa.Column("configured_tags", _json_type(), nullable=False),
        sa.Column("manual_tags", _json_type(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("os_override", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f("ix_nodes_name"), "nodes", ["name"], unique=True)
    op.create_index(op.f("ix_nodes_expected_vpn_ip"), "nodes", ["expected_vpn_ip"], unique=False)

    op.create_table(
        "dns_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("record_type", sa.String(length=20), nullable=False),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column("matched_node", sa.String(length=120), nullable=True),
        sa.Column("outside_vpn", sa.Boolean(), nullable=False),
        sa.Column("warning", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("hostname", "record_type", "target", name="uq_dns_record"),
    )
    op.create_index(op.f("ix_dns_records_hostname"), "dns_records", ["hostname"], unique=False)

    op.create_table(
        "warnings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("node_name", sa.String(length=120), nullable=True),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f("ix_warnings_node_name"), "warnings", ["node_name"], unique=False)
    op.create_index(op.f("ix_warnings_source"), "warnings", ["source"], unique=False)

    op.create_table(
        "snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("node_id", sa.Integer(), sa.ForeignKey("nodes.id"), nullable=False),
        sa.Column("snapshot", _json_type(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reachable", sa.Boolean(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index(op.f("ix_snapshots_node_id"), "snapshots", ["node_id"], unique=False)
    op.create_index(op.f("ix_snapshots_collected_at"), "snapshots", ["collected_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_snapshots_collected_at"), table_name="snapshots")
    op.drop_index(op.f("ix_snapshots_node_id"), table_name="snapshots")
    op.drop_table("snapshots")
    op.drop_index(op.f("ix_warnings_source"), table_name="warnings")
    op.drop_index(op.f("ix_warnings_node_name"), table_name="warnings")
    op.drop_table("warnings")
    op.drop_index(op.f("ix_dns_records_hostname"), table_name="dns_records")
    op.drop_table("dns_records")
    op.drop_index(op.f("ix_nodes_expected_vpn_ip"), table_name="nodes")
    op.drop_index(op.f("ix_nodes_name"), table_name="nodes")
    op.drop_table("nodes")

