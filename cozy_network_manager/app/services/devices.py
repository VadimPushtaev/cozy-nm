from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

from sqlalchemy.orm import Session

from cozy_network_manager.app.db.models import Node
from cozy_network_manager.app.services.nodes import latest_snapshot


@dataclass(frozen=True)
class WireGuardDevice:
    ip: str
    allowed_ip: str
    source_node: str
    interface: str
    public_key: str
    endpoint: str | None
    latest_handshake: int | None
    handshake_age_seconds: int | None
    transfer_rx: int | None
    transfer_tx: int | None
    online: bool
    configured_name: str | None = None
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["tags"] = list(self.tags)
        return data


def _subnets(raw_subnets: list[str]):
    return [ip_network(raw, strict=False) for raw in raw_subnets]


def _device_ip(raw_allowed_ip: str, networks) -> tuple[str, str] | None:
    try:
        interface = ip_interface(raw_allowed_ip)
    except ValueError:
        try:
            interface = ip_interface(f"{ip_address(raw_allowed_ip)}/32")
        except ValueError:
            return None
    if any(interface.ip in network for network in networks):
        return str(interface.ip), str(interface)
    return None


def _handshake_age(latest_handshake: int | None, now: datetime) -> int | None:
    if not latest_handshake:
        return None
    return max(0, int(now.timestamp() - latest_handshake))


def _configured_node_by_ip(
    db: Session, networks, active_node_names: set[str] | None = None
) -> dict[str, Node]:
    nodes: dict[str, Node] = {}
    for node in db.query(Node).order_by(Node.name).all():
        if active_node_names is not None and node.name not in active_node_names:
            continue
        match = _device_ip(node.expected_vpn_ip, networks)
        if match:
            nodes[match[0]] = node
    return nodes


def _tags_for(node: Node | None) -> tuple[str, ...]:
    if node is None:
        return ()
    return tuple(sorted(set(node.configured_tags + node.manual_tags)))


def _device_score(device: WireGuardDevice) -> tuple[int, int, int]:
    return (
        1 if device.online else 0,
        device.latest_handshake or 0,
        (device.transfer_rx or 0) + (device.transfer_tx or 0),
    )


def extract_wireguard_devices(
    snapshot: dict[str, Any],
    source_node: str,
    subnets: list[str],
    stale_after_seconds: int,
    now: datetime | None = None,
    configured_nodes: dict[str, Node] | None = None,
) -> list[WireGuardDevice]:
    networks = _subnets(subnets)
    now = now or datetime.now(timezone.utc)
    configured_nodes = configured_nodes or {}
    devices: list[WireGuardDevice] = []

    for iface in snapshot.get("wireguard", []):
        interface_name = iface.get("name", "")
        for peer in iface.get("peers", []):
            for allowed_ip in peer.get("allowed_ips", []):
                match = _device_ip(allowed_ip, networks)
                if not match:
                    continue
                ip, normalized_allowed_ip = match
                latest_handshake = peer.get("latest_handshake")
                age_seconds = _handshake_age(latest_handshake, now)
                configured_node = configured_nodes.get(ip)
                devices.append(
                    WireGuardDevice(
                        ip=ip,
                        allowed_ip=normalized_allowed_ip,
                        source_node=source_node,
                        interface=interface_name,
                        public_key=peer.get("public_key", ""),
                        endpoint=peer.get("endpoint"),
                        latest_handshake=latest_handshake,
                        handshake_age_seconds=age_seconds,
                        transfer_rx=peer.get("transfer_rx"),
                        transfer_tx=peer.get("transfer_tx"),
                        online=age_seconds is not None and age_seconds <= stale_after_seconds,
                        configured_name=configured_node.name if configured_node else None,
                        tags=_tags_for(configured_node),
                    )
                )
    return devices


def wireguard_device_inventory(
    db: Session,
    subnets: list[str],
    stale_after_seconds: int,
    active_node_names: set[str] | None = None,
) -> list[WireGuardDevice]:
    networks = _subnets(subnets)
    configured_nodes = _configured_node_by_ip(db, networks, active_node_names)
    by_ip: dict[str, WireGuardDevice] = {}
    now = datetime.now(timezone.utc)

    for node in db.query(Node).order_by(Node.name).all():
        snapshot = latest_snapshot(db, node.id)
        if snapshot is None:
            continue
        for device in extract_wireguard_devices(
            snapshot.snapshot,
            node.name,
            subnets,
            stale_after_seconds,
            now=now,
            configured_nodes=configured_nodes,
        ):
            current = by_ip.get(device.ip)
            if current is None or _device_score(device) > _device_score(current):
                by_ip[device.ip] = device

    for ip, node in configured_nodes.items():
        if ip not in by_ip:
            by_ip[ip] = WireGuardDevice(
                ip=ip,
                allowed_ip=node.expected_vpn_ip,
                source_node="configured",
                interface="",
                public_key="",
                endpoint=node.minion_api_url,
                latest_handshake=None,
                handshake_age_seconds=None,
                transfer_rx=None,
                transfer_tx=None,
                online=False,
                configured_name=node.name,
                tags=_tags_for(node),
            )

    return sorted(by_ip.values(), key=lambda device: ip_address(device.ip))
