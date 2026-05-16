from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from cozy_network_manager.app.config import get_config
from cozy_network_manager.app.db.models import Device, DnsRecord, Node, SnapshotRecord, WarningEvent
from cozy_network_manager.app.db.session import get_db
from cozy_network_manager.app.services.devices import device_inventory
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


def _device_payload(device: Device):
    return {
        "name": device.name,
        "ip": device.ip,
        "address": device.address,
        "interface": device.interface,
        "endpoint": device.endpoint,
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
    return {config.node_name, *(known.name for known in config.known_nodes)}


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


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    config = get_config()
    active_node_names = _active_node_names(config)
    visible_node_names = _visible_node_names(db, active_node_names)
    nodes = node_summary(db, config.stale_after_seconds, active_node_names)
    devices = device_inventory(db)
    network_rows = [
        {"label": device.name, "online": device.wg_connected} for device in devices
    ] or [{"label": row["node"].name, "online": row["online"]} for row in nodes]
    dns = db.query(DnsRecord).order_by(DnsRecord.hostname, DnsRecord.record_type).all()
    warnings = _visible_warnings(db, visible_node_names, 10)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "nodes": nodes,
            "devices": devices,
            "network_rows": network_rows,
            "device_subnets": config.device_subnets,
            "dns_records": dns,
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
            "devices": device_inventory(db),
            "device_subnets": config.device_subnets,
        },
    )


@router.get("/nodes/{name}", response_class=HTMLResponse)
def node_detail(request: Request, name: str, db: Session = Depends(get_db)):
    node = db.query(Node).filter(Node.name == name).one_or_none()
    if node is None:
        raise HTTPException(status_code=404)
    snapshot = latest_snapshot(db, node.id)
    return templates.TemplateResponse(
        request,
        "node_detail.html",
        {"node": node, "snapshot": snapshot},
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
def forwards_page(request: Request, db: Session = Depends(get_db)):
    rows = []
    for node in db.query(Node).order_by(Node.name).all():
        snapshot = latest_snapshot(db, node.id)
        if not snapshot:
            continue
        for forward in snapshot.snapshot.get("socat_forwards", []):
            rows.append({"node": node, "forward": forward, "snapshot": snapshot})
    return templates.TemplateResponse(request, "forwards.html", {"rows": rows})


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
    return [_device_payload(device) for device in device_inventory(db)]


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
