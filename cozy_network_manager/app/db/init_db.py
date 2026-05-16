from __future__ import annotations

from sqlalchemy.orm import Session

from cozy_network_manager.app.config import AppConfig
from cozy_network_manager.app.db.models import Node
from cozy_network_manager.app.db.session import Base, engine


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


def sync_configured_nodes(db: Session, config: AppConfig) -> None:
    for known in config.known_nodes:
        node = db.query(Node).filter(Node.name == known.name).one_or_none()
        if node is None:
            node = Node(name=known.name, expected_vpn_ip=known.expected_vpn_ip)
            db.add(node)
        node.expected_vpn_ip = known.expected_vpn_ip
        node.minion_api_url = str(known.minion_api_url) if known.minion_api_url else None
        node.configured_tags = known.tags
        if not node.notes and known.notes:
            node.notes = known.notes
        node.os_override = known.os_override
    db.commit()

