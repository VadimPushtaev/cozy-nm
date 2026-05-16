from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc
from sqlalchemy.orm import Session

from cozy_network_manager.app.db.models import Node, SnapshotRecord, WarningEvent
from cozy_network_manager.app.schemas import Snapshot


def get_or_create_node(db: Session, name: str, expected_vpn_ip: str = "unknown") -> Node:
    node = db.query(Node).filter(Node.name == name).one_or_none()
    if node:
        return node
    node = Node(name=name, expected_vpn_ip=expected_vpn_ip)
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


def store_snapshot(db: Session, node: Node, snapshot: Snapshot, reachable: bool = True) -> SnapshotRecord:
    record = SnapshotRecord(
        node_id=node.id,
        snapshot=snapshot.model_dump(mode="json"),
        collected_at=snapshot.timestamp,
        reachable=reachable,
    )
    db.add(record)
    for item in [*snapshot.warnings, *snapshot.errors]:
        db.add(WarningEvent(node_name=node.name, source=item.source, message=item.message))
    db.commit()
    db.refresh(record)
    return record


def store_poll_error(db: Session, node: Node, source: str, message: str) -> None:
    db.add(WarningEvent(node_name=node.name, source=source, message=message))
    db.commit()


def latest_snapshot(db: Session, node_id: int) -> SnapshotRecord | None:
    return (
        db.query(SnapshotRecord)
        .filter(SnapshotRecord.node_id == node_id)
        .order_by(desc(SnapshotRecord.collected_at))
        .first()
    )


def node_summary(
    db: Session,
    stale_after_seconds: int,
    active_node_names: set[str] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for node in db.query(Node).order_by(Node.name).all():
        snapshot = latest_snapshot(db, node.id)
        if active_node_names is not None and node.name not in active_node_names and snapshot is None:
            continue
        stale = True
        age_seconds = None
        if snapshot:
            collected_at = snapshot.collected_at
            if collected_at.tzinfo is None:
                collected_at = collected_at.replace(tzinfo=timezone.utc)
            age_seconds = (now - collected_at).total_seconds()
            stale = age_seconds > stale_after_seconds
        rows.append(
            {
                "node": node,
                "snapshot": snapshot,
                "stale": stale,
                "age_seconds": age_seconds,
                "online": bool(snapshot and not stale),
                "manual_only": not node.minion_api_url,
            }
        )
    return rows
