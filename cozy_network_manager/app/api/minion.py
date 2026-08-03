from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException

from cozy_network_manager.app.collectors.host import collect_public_ipv4
from cozy_network_manager.app.collectors.snapshot import collect_snapshot
from cozy_network_manager.app.config import get_config
from cozy_network_manager.app.schemas import (
    BridgeDefinitionInput,
    BridgeOperationResult,
    BridgeProject,
    utc_now,
)
from cozy_network_manager.app.services.bridges import BridgeManager, BridgeManagerError


router = APIRouter()


def require_bridge_token(authorization: str | None = Header(default=None)) -> None:
    config = get_config()
    if config.mode != "minion":
        raise HTTPException(status_code=404)
    expected = config.bridge_api_token
    if not expected:
        raise HTTPException(status_code=503, detail="Bridge management token is not configured.")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid bridge management token.")


def bridge_manager() -> BridgeManager:
    try:
        return BridgeManager(get_config())
    except BridgeManagerError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


def bridge_error(exc: BridgeManagerError) -> HTTPException:
    detail = {"message": str(exc)}
    if hasattr(exc, "stdout"):
        detail["stdout"] = getattr(exc, "stdout")
        detail["stderr"] = getattr(exc, "stderr")
    return HTTPException(status_code=exc.status_code, detail=detail)


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


@router.get(
    "/api/v1/bridges",
    response_model=BridgeProject,
    dependencies=[Depends(require_bridge_token)],
)
def bridges(manager: BridgeManager = Depends(bridge_manager)):
    return manager.project()


@router.post(
    "/api/v1/bridges",
    response_model=BridgeProject,
    dependencies=[Depends(require_bridge_token)],
)
def create_bridge(value: BridgeDefinitionInput, manager: BridgeManager = Depends(bridge_manager)):
    try:
        return manager.create(value)
    except BridgeManagerError as exc:
        raise bridge_error(exc) from exc


@router.put(
    "/api/v1/bridges/{name}",
    response_model=BridgeProject,
    dependencies=[Depends(require_bridge_token)],
)
def update_bridge(
    name: str,
    value: BridgeDefinitionInput,
    manager: BridgeManager = Depends(bridge_manager),
):
    try:
        return manager.update(name, value)
    except BridgeManagerError as exc:
        raise bridge_error(exc) from exc


@router.delete(
    "/api/v1/bridges/{name}",
    response_model=BridgeProject,
    dependencies=[Depends(require_bridge_token)],
)
def delete_bridge(name: str, manager: BridgeManager = Depends(bridge_manager)):
    try:
        return manager.delete(name)
    except BridgeManagerError as exc:
        raise bridge_error(exc) from exc


@router.post(
    "/api/v1/bridges/{name}/actions/{action}",
    response_model=BridgeOperationResult,
    dependencies=[Depends(require_bridge_token)],
)
def bridge_action(
    name: str,
    action: str,
    manager: BridgeManager = Depends(bridge_manager),
):
    try:
        return manager.service_action(name, action)
    except BridgeManagerError as exc:
        raise bridge_error(exc) from exc


@router.post(
    "/api/v1/bridges/project/apply",
    response_model=BridgeOperationResult,
    dependencies=[Depends(require_bridge_token)],
)
def apply_bridge_project(manager: BridgeManager = Depends(bridge_manager)):
    try:
        return manager.apply_project()
    except BridgeManagerError as exc:
        raise bridge_error(exc) from exc


@router.post(
    "/api/v1/bridges/project/restart",
    response_model=BridgeOperationResult,
    dependencies=[Depends(require_bridge_token)],
)
def restart_bridge_project(manager: BridgeManager = Depends(bridge_manager)):
    try:
        return manager.restart_project()
    except BridgeManagerError as exc:
        raise bridge_error(exc) from exc
