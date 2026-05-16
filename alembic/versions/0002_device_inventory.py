from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0002_device_inventory"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("ip", sa.String(length=120), nullable=False),
        sa.Column("address", sa.String(length=120), nullable=False),
        sa.Column("public_key", sa.String(length=120), nullable=False),
        sa.Column("config_path", sa.String(length=500), nullable=False),
        sa.Column("interface", sa.String(length=120), nullable=True),
        sa.Column("endpoint", sa.String(length=255), nullable=True),
        sa.Column("latest_handshake", sa.BigInteger(), nullable=True),
        sa.Column("transfer_rx", sa.BigInteger(), nullable=True),
        sa.Column("transfer_tx", sa.BigInteger(), nullable=True),
        sa.Column("wg_connected", sa.Boolean(), nullable=False),
        sa.Column("pingable", sa.Boolean(), nullable=False),
        sa.Column("minion_available", sa.Boolean(), nullable=False),
        sa.Column("minion_url", sa.String(length=500), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f("ix_devices_name"), "devices", ["name"], unique=True)
    op.create_index(op.f("ix_devices_ip"), "devices", ["ip"], unique=False)
    op.create_index(op.f("ix_devices_public_key"), "devices", ["public_key"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_devices_public_key"), table_name="devices")
    op.drop_index(op.f("ix_devices_ip"), table_name="devices")
    op.drop_index(op.f("ix_devices_name"), table_name="devices")
    op.drop_table("devices")
