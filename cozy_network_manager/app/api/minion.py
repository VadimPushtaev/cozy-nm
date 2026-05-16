from __future__ import annotations

from fastapi import APIRouter

from cozy_network_manager.app.collectors.snapshot import collect_snapshot
from cozy_network_manager.app.config import get_config
from cozy_network_manager.app.schemas import utc_now


router = APIRouter()


@router.get("/health")
def health():
    config = get_config()
    return {
        "status": "ok",
        "mode": config.mode,
        "node_name": config.node_name,
        "timestamp": utc_now(),
    }


@router.get("/api/v1/snapshot")
def snapshot():
    return collect_snapshot(get_config())

