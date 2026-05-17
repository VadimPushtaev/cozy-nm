from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from cozy_network_manager.app.db.session import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


JsonType = JSON().with_variant(JSONB, "postgresql")


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    expected_vpn_ip: Mapped[str] = mapped_column(String(120), index=True)
    minion_api_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    configured_tags: Mapped[list[str]] = mapped_column(JsonType, default=list)
    manual_tags: Mapped[list[str]] = mapped_column(JsonType, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    os_override: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc
    )

    snapshots: Mapped[list["SnapshotRecord"]] = relationship(back_populates="node")


class SnapshotRecord(Base):
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    snapshot: Mapped[dict] = mapped_column(JsonType)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    reachable: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    node: Mapped[Node] = relationship(back_populates="snapshots")


class DnsRecord(Base):
    __tablename__ = "dns_records"
    __table_args__ = (UniqueConstraint("hostname", "record_type", "target", name="uq_dns_record"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    record_type: Mapped[str] = mapped_column(String(20))
    target: Mapped[str] = mapped_column(String(500))
    matched_node: Mapped[str | None] = mapped_column(String(120), nullable=True)
    outside_vpn: Mapped[bool] = mapped_column(Boolean, default=False)
    warning: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    ip: Mapped[str] = mapped_column(String(120), index=True)
    address: Mapped[str] = mapped_column(String(120))
    public_key: Mapped[str] = mapped_column(String(120), index=True)
    config_path: Mapped[str] = mapped_column(String(500))
    interface: Mapped[str | None] = mapped_column(String(120), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    latest_handshake: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    transfer_rx: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    transfer_tx: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    wg_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    pingable: Mapped[bool] = mapped_column(Boolean, default=False)
    minion_available: Mapped[bool] = mapped_column(Boolean, default=False)
    minion_url: Mapped[str] = mapped_column(String(500))
    last_checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc
    )

    @property
    def public_ip(self) -> str | None:
        if not self.endpoint:
            return None
        host = self.endpoint.rsplit(":", 1)[0].strip("[]")
        try:
            parsed = ip_address(host)
        except ValueError:
            return None
        return str(parsed) if parsed.is_global else None


class WarningEvent(Base):
    __tablename__ = "warnings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_name: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(120), index=True)
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
