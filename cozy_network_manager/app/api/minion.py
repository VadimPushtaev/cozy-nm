from __future__ import annotations

from fastapi import APIRouter

from cozy_network_manager.app.collectors.host import collect_public_ipv4
from cozy_network_manager.app.collectors.snapshot import collect_snapshot
from cozy_network_manager.app.config import get_config
from cozy_network_manager.app.schemas import utc_now


router = APIRouter()


@router.get("/health")
def health():
    config = get_config()
    public_ipv4, public_ipv4_warning = collect_public_ipv4(config.public_ipv4_url)
    return {
        "status": "ok",
        "mode": config.mode,
        "node_name": config.node_identifier(),
        "node_ip": config.node_ip,
        "public_ipv4": public_ipv4,
        "public_ipv4_error": public_ipv4_warning.message if public_ipv4_warning else None,
        "timestamp": utc_now(),
    }


@router.get("/api/v1/snapshot")
def snapshot():
    return collect_snapshot(get_config())
