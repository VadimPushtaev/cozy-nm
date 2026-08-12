from __future__ import annotations

import socket
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from cozy_network_manager.app.config import get_config
from cozy_network_manager.app.db.models import Device, DnsRecord, Node, SnapshotRecord, WarningEvent
from cozy_network_manager.app.db.session import get_db
from cozy_network_manager.app.services.devices import device_inventory
from cozy_network_manager.app.services.bridge_client import (
    BridgeClientError,
    bridge_action as call_bridge_action,
    create_bridge as call_create_bridge,
    delete_bridge as call_delete_bridge,
    fetch_bridge_projects,
    project_action as call_project_action,
    update_bridge as call_update_bridge,
)
from cozy_network_manager.app.services.nodes import latest_snapshot, node_summary
from cozy_network_manager.app.ui.templates import templates


router = APIRouter()


def _node_payload(node: Node):
    return {
        "name": node.name,
        "expected_vpn_ip": node.expected_vpn_ip,
        "minion_api_url": node.minion_api_url,
        "configured_tags": node.configured_tags,
        "manual_tags": node.manual_tags,
        "tags": sorted(set(node.configured_tags + node.manual_tags)),
        "notes": node.notes,
        "os_override": node.os_override,
    }


def _device_client_label(device: Device, config) -> str:
    return "head" if config.deployment.head and device.ip == config.deployment.head else device.name


def _reverse_hostname(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        return None
    return name.rstrip(".") or None


def _latest_hostnames_by_ip(db: Session) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in db.query(Node).order_by(Node.name).all():
        snapshot = latest_snapshot(db, node.id)
        hostname = (snapshot.snapshot.get("host") or {}).get("hostname") if snapshot else None
        if hostname:
            values[node.expected_vpn_ip] = hostname
    return values


def _device_rows(db: Session, config) -> list[dict]:
    hostnames_by_ip = _latest_hostnames_by_ip(db)
    rows = []
    for device in device_inventory(db):
        hostname = hostnames_by_ip.get(device.ip) or _reverse_hostname(device.ip)
        if not hostname and device.name != device.ip:
            hostname = device.name
        rows.append(
            {
                "device": device,
                "client": _device_client_label(device, config),
                "hostname": hostname or "",
            }
        )
    return rows


def _device_payload(device: Device, config, hostname: str = ""):
    return {
        "name": device.name,
        "client": _device_client_label(device, config),
        "hostname": hostname,
        "ip": device.ip,
        "address": device.address,
        "interface": device.interface,
        "endpoint": device.endpoint,
        "public_ip": device.current_public_ip,
        "last_public_ip": device.public_ip,
        "latest_handshake": device.latest_handshake,
        "transfer_rx": device.transfer_rx,
        "transfer_tx": device.transfer_tx,
        "wg_connected": device.wg_connected,
        "pingable": device.pingable,
        "minion_available": device.minion_available,
        "minion_url": device.minion_url,
        "last_checked_at": device.last_checked_at,
    }


def _active_node_names(config) -> set[str]:
    return {config.node_identifier(), *(known.name for known in config.topology_nodes())}


def _visible_node_names(db: Session, active_node_names: set[str]) -> set[str]:
    snapshot_node_names = {
        name
        for (name,) in db.query(Node.name).join(SnapshotRecord, SnapshotRecord.node_id == Node.id).all()
    }
    return active_node_names | snapshot_node_names


def _visible_warnings(db: Session, visible_node_names: set[str], limit: int) -> list[WarningEvent]:
    warnings = db.query(WarningEvent).order_by(WarningEvent.created_at.desc()).limit(200).all()
    return [
        warning
        for warning in warnings
        if warning.node_name is None or warning.node_name in visible_node_names
    ][:limit]


def _bridge_projects(db: Session, config) -> list[dict]:
    device_names_by_ip = {device.ip: device.name for device in device_inventory(db)}
    hostnames_by_ip = _latest_hostnames_by_ip(db)
    projects = fetch_bridge_projects(config)
    for project in projects:
        project["hostname"] = hostnames_by_ip.get(project["node_ip"], "")
        for bridge in project["services"]:
            bridge["destination_device"] = device_names_by_ip.get(bridge.get("target_host"))
    return projects


def _bridge_rows(projects: list[dict]) -> list[dict]:
    return [
        {"project": project, "bridge": bridge}
        for project in projects
        for bridge in project["services"]
    ]


def _snapshot_is_stale(snapshot: SnapshotRecord, stale_after_seconds: int) -> bool:
    collected_at = snapshot.collected_at
    if collected_at.tzinfo is None:
        collected_at = collected_at.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - collected_at).total_seconds() > stale_after_seconds


def _public_interface_rows(db: Session, stale_after_seconds: int) -> list[dict]:
    rows = []
    for node in db.query(Node).order_by(Node.name).all():
        snapshot = latest_snapshot(db, node.id)
        if snapshot is None:
            continue
        stale = _snapshot_is_stale(snapshot, stale_after_seconds)
        for interface in snapshot.snapshot.get("public_interfaces", []):
            rows.append(
                {
                    "node": node,
                    "service": interface.get("service", "unknown"),
                    "url": interface.get("url", ""),
                    "status": "stale" if stale else interface.get("status", "down"),
                }
            )
    return sorted(rows, key=lambda row: (row["node"].name, row["service"], row["url"]))


def _same_origin(request: Request) -> None:
    expected_host = request.headers.get("host", "")
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    supplied = origin or referer
    if not supplied or urlparse(supplied).netloc != expected_host:
        raise HTTPException(status_code=403, detail="Bridge actions require a same-origin form submission.")


def _forwards_redirect(*, message: str | None = None, error: str | None = None):
    query = urlencode({key: value for key, value in {"message": message, "error": error}.items() if value})
    return RedirectResponse(f"/forwards{f'?{query}' if query else ''}", status_code=303)


def _bridge_form_payload(name: str, listen_port: int, target_host: str, target_port: int):
    return {
        "name": name.strip(),
        "listen_port": listen_port,
        "target_host": target_host.strip(),
        "target_port": target_port,
    }


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    config = get_config()
    active_node_names = _active_node_names(config)
    visible_node_names = _visible_node_names(db, active_node_names)
    nodes = node_summary(db, config.stale_after_seconds, active_node_names)
    device_rows = _device_rows(db, config)
    devices = [row["device"] for row in device_rows]
    dns = db.query(DnsRecord).order_by(DnsRecord.hostname, DnsRecord.record_type).all()
    bridge_projects = _bridge_projects(db, config)
    warnings = _visible_warnings(db, visible_node_names, 10)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "nodes": nodes,
            "devices": devices,
            "device_rows": device_rows,
            "device_subnets": config.device_subnets,
            "dns_records": dns,
            "public_interface_rows": _public_interface_rows(db, config.stale_after_seconds),
            "forward_rows": _bridge_rows(bridge_projects),
            "bridge_projects": bridge_projects,
            "warnings": warnings,
        },
    )


@router.get("/nodes", response_class=HTMLResponse)
def nodes_page(request: Request, db: Session = Depends(get_db)):
    config = get_config()
    active_node_names = _active_node_names(config)
    return templates.TemplateResponse(
        request,
        "nodes.html",
        {
            "nodes": node_summary(db, config.stale_after_seconds, active_node_names),
            "device_rows": _device_rows(db, config),
            "device_subnets": config.device_subnets,
        },
    )


@router.get("/nodes/{name}", response_class=HTMLResponse)
def node_detail(request: Request, name: str, db: Session = Depends(get_db)):
    node = db.query(Node).filter(Node.name == name).one_or_none()
    if node is None:
        raise HTTPException(status_code=404)
    snapshot = latest_snapshot(db, node.id)
    config = get_config()
    return templates.TemplateResponse(
        request,
        "node_detail.html",
        {
            "node": node,
            "snapshot": snapshot,
            "snapshot_stale": bool(
                snapshot and _snapshot_is_stale(snapshot, config.stale_after_seconds)
            ),
        },
    )


@router.post("/nodes/{name}/metadata")
def update_node_metadata(
    name: str,
    tags: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    node = db.query(Node).filter(Node.name == name).one_or_none()
    if node is None:
        raise HTTPException(status_code=404)
    node.manual_tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
    node.notes = notes
    db.commit()
    return RedirectResponse(f"/nodes/{name}", status_code=303)


@router.get("/dns", response_class=HTMLResponse)
def dns_page(request: Request, db: Session = Depends(get_db)):
    records = db.query(DnsRecord).order_by(DnsRecord.hostname, DnsRecord.record_type).all()
    return templates.TemplateResponse(request, "dns.html", {"records": records})


@router.get("/forwards", response_class=HTMLResponse)
def forwards_page(
    request: Request,
    message: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    config = get_config()
    return templates.TemplateResponse(
        request,
        "forwards.html",
        {
            "projects": _bridge_projects(db, config),
            "message": message,
            "error": error,
        },
    )


@router.get("/forwards/{node_ip}/bridges/new", response_class=HTMLResponse)
def new_bridge_page(request: Request, node_ip: str):
    config = get_config()
    host = config.bridge_host(node_ip)
    if host is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request,
        "bridge_form.html",
        {"node_ip": node_ip, "bridge": None, "compose_dir": host.compose_dir},
    )


@router.get("/forwards/{node_ip}/bridges/{name}/edit", response_class=HTMLResponse)
def edit_bridge_page(request: Request, node_ip: str, name: str, db: Session = Depends(get_db)):
    projects = _bridge_projects(db, get_config())
    project = next((item for item in projects if item["node_ip"] == node_ip), None)
    bridge = next(
        (item for item in (project or {}).get("services", []) if item["name"] == name),
        None,
    )
    if project is None or bridge is None:
        raise HTTPException(status_code=404)
    if not bridge.get("managed"):
        raise HTTPException(status_code=409, detail="Unsupported bridge definitions are read-only.")
    return templates.TemplateResponse(
        request,
        "bridge_form.html",
        {
            "node_ip": node_ip,
            "bridge": bridge,
            "compose_dir": project["compose_dir"],
        },
    )


@router.post("/forwards/{node_ip}/bridges")
def create_bridge_route(
    request: Request,
    node_ip: str,
    name: str = Form(...),
    listen_port: int = Form(...),
    target_host: str = Form(...),
    target_port: int = Form(...),
):
    _same_origin(request)
    try:
        call_create_bridge(
            get_config(),
            node_ip,
            _bridge_form_payload(name, listen_port, target_host, target_port),
        )
    except BridgeClientError as exc:
        return _forwards_redirect(error=str(exc))
    return _forwards_redirect(message=f"Bridge {name.strip()} saved; apply the project to enact it.")


@router.post("/forwards/{node_ip}/bridges/{current_name}/edit")
def update_bridge_route(
    request: Request,
    node_ip: str,
    current_name: str,
    name: str = Form(...),
    listen_port: int = Form(...),
    target_host: str = Form(...),
    target_port: int = Form(...),
):
    _same_origin(request)
    try:
        call_update_bridge(
            get_config(),
            node_ip,
            current_name,
            _bridge_form_payload(name, listen_port, target_host, target_port),
        )
    except BridgeClientError as exc:
        return _forwards_redirect(error=str(exc))
    return _forwards_redirect(message=f"Bridge {name.strip()} saved; apply the project to enact it.")


@router.post("/forwards/{node_ip}/bridges/{name}/delete")
def delete_bridge_route(request: Request, node_ip: str, name: str):
    _same_origin(request)
    try:
        call_delete_bridge(get_config(), node_ip, name)
    except BridgeClientError as exc:
        return _forwards_redirect(error=str(exc))
    return _forwards_redirect(message=f"Bridge {name} removed from configuration; apply the project to enact it.")


@router.post("/forwards/{node_ip}/bridges/{name}/actions/{action}")
def bridge_action_route(request: Request, node_ip: str, name: str, action: str):
    _same_origin(request)
    if action not in {"start", "stop", "restart"}:
        raise HTTPException(status_code=404)
    try:
        result = call_bridge_action(get_config(), node_ip, name, action)
    except BridgeClientError as exc:
        return _forwards_redirect(error=str(exc))
    return _forwards_redirect(message=result.get("message") or f"Bridge {action} completed.")


@router.post("/forwards/{node_ip}/project/{action}")
def bridge_project_action_route(request: Request, node_ip: str, action: str):
    _same_origin(request)
    if action not in {"apply", "restart"}:
        raise HTTPException(status_code=404)
    try:
        result = call_project_action(get_config(), node_ip, action)
    except BridgeClientError as exc:
        return _forwards_redirect(error=str(exc))
    return _forwards_redirect(message=result.get("message") or f"Project {action} completed.")


@router.get("/warnings", response_class=HTMLResponse)
def warnings_page(request: Request, db: Session = Depends(get_db)):
    config = get_config()
    visible_node_names = _visible_node_names(db, _active_node_names(config))
    warnings = _visible_warnings(db, visible_node_names, 200)
    return templates.TemplateResponse(request, "warnings.html", {"warnings": warnings})


@router.get("/api/v1/nodes")
def api_nodes(db: Session = Depends(get_db)):
    config = get_config()
    active_node_names = _active_node_names(config)
    return [
        {
            "name": row["node"].name,
            "expected_vpn_ip": row["node"].expected_vpn_ip,
            "tags": sorted(set(row["node"].configured_tags + row["node"].manual_tags)),
            "notes": row["node"].notes,
            "online": row["online"],
            "stale": row["stale"],
        }
        for row in node_summary(db, config.stale_after_seconds, active_node_names)
    ]


@router.get("/api/v1/devices")
def api_devices(db: Session = Depends(get_db)):
    config = get_config()
    return [
        _device_payload(row["device"], config, row["hostname"])
        for row in _device_rows(db, config)
    ]


@router.get("/api/v1/nodes/{name}")
def api_node(name: str, db: Session = Depends(get_db)):
    node = db.query(Node).filter(Node.name == name).one_or_none()
    if node is None:
        raise HTTPException(status_code=404)
    return _node_payload(node)


@router.get("/api/v1/snapshots/{name}")
def api_snapshot(name: str, db: Session = Depends(get_db)):
    node = db.query(Node).filter(Node.name == name).one_or_none()
    if node is None:
        raise HTTPException(status_code=404)
    snapshot = latest_snapshot(db, node.id)
    if snapshot is None:
        raise HTTPException(status_code=404)
    return snapshot.snapshot
