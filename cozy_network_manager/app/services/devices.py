from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path
import shutil
import subprocess

import httpx
from sqlalchemy.orm import Session

from cozy_network_manager.app.config import AppConfig
from cozy_network_manager.app.db.models import Device


@dataclass(frozen=True)
class ClientConfig:
    name: str
    ip: str
    address: str
    public_key: str
    config_path: str


@dataclass(frozen=True)
class PeerState:
    interface: str
    public_key: str
    endpoint: str | None
    latest_handshake: int | None
    transfer_rx: int | None
    transfer_tx: int | None


@dataclass(frozen=True)
class DeviceStatus:
    name: str
    ip: str
    address: str
    public_key: str
    config_path: str
    interface: str | None
    endpoint: str | None
    latest_handshake: int | None
    transfer_rx: int | None
    transfer_tx: int | None
    wg_connected: bool
    pingable: bool
    minion_available: bool
    minion_url: str
    last_checked_at: datetime


def _subnets(raw_subnets: list[str]):
    return [ip_network(raw, strict=False) for raw in raw_subnets]


def _read_conf_value(text: str, section: str, key: str) -> str | None:
    current_section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            continue
        if current_section != section or "=" not in line:
            continue
        found_key, value = line.split("=", 1)
        if found_key.strip() == key:
            return value.strip()
    return None


def _client_ip(address: str, networks) -> str | None:
    for raw_address in address.split(","):
        raw_address = raw_address.strip()
        if not raw_address:
            continue
        try:
            interface = ip_interface(raw_address)
        except ValueError:
            continue
        if any(interface.ip in network for network in networks):
            return str(interface.ip)
    return None


def _ip_in_subnets(ip: str, subnets: list[str]) -> bool:
    address = ip_address(ip)
    return any(address in network for network in _subnets(subnets))


def parse_client_config(config_path: Path, subnets: list[str]) -> ClientConfig | None:
    networks = _subnets(subnets)
    text = config_path.read_text(encoding="utf-8")
    address = _read_conf_value(text, "Interface", "Address")
    if not address:
        return None
    ip = _client_ip(address, networks)
    if ip is None:
        return None

    public_key_path = config_path.with_suffix(".pub")
    public_key = ""
    if public_key_path.exists():
        public_key = public_key_path.read_text(encoding="utf-8").strip()

    return ClientConfig(
        name=config_path.stem,
        ip=ip,
        address=address,
        public_key=public_key,
        config_path=str(config_path),
    )


def load_client_configs(clients_path: str, subnets: list[str]) -> list[ClientConfig]:
    path = Path(clients_path)
    if not path.exists() or not path.is_dir():
        return []
    clients = []
    for config_path in sorted(path.glob("*.conf")):
        try:
            client = parse_client_config(config_path, subnets)
        except OSError:
            continue
        if client:
            clients.append(client)
    return clients


def _to_int(value: str) -> int | None:
    if value in {"", "(none)", "off"}:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_wg_peer_states(output: str) -> dict[str, PeerState]:
    peers: dict[str, PeerState] = {}
    for raw_line in output.splitlines():
        parts = raw_line.strip().split("\t")
        if len(parts) != 9:
            continue
        (
            interface,
            public_key,
            _preshared_key,
            endpoint,
            _allowed_ips,
            latest_handshake,
            transfer_rx,
            transfer_tx,
            _persistent_keepalive,
        ) = parts
        peers[public_key] = PeerState(
            interface=interface,
            public_key=public_key,
            endpoint=None if endpoint == "(none)" else endpoint,
            latest_handshake=_to_int(latest_handshake),
            transfer_rx=_to_int(transfer_rx),
            transfer_tx=_to_int(transfer_tx),
        )
    return peers


def load_wg_peer_states() -> dict[str, PeerState]:
    if not shutil.which("wg"):
        return {}
    result = subprocess.run(
        ["wg", "show", "all", "dump"],
        capture_output=True,
        check=False,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        return {}
    return parse_wg_peer_states(result.stdout)


def _is_connected(peer: PeerState | None, stale_after_seconds: int, now: datetime) -> bool:
    if peer is None or not peer.latest_handshake:
        return False
    return now.timestamp() - peer.latest_handshake <= stale_after_seconds


def ping_ip(ip: str) -> bool:
    if not shutil.which("ping"):
        return False
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],
        capture_output=True,
        check=False,
        text=True,
        timeout=3,
    )
    return result.returncode == 0


def minion_available(url: str) -> bool:
    try:
        response = httpx.get(url.rstrip("/") + "/health", timeout=2)
    except Exception:
        return False
    return response.status_code == 200


def scan_wireguard_clients(config: AppConfig) -> list[DeviceStatus]:
    clients = load_client_configs(config.wireguard_clients_path, config.device_subnets)
    peers = load_wg_peer_states()
    now = datetime.now(timezone.utc)
    statuses = []
    client_ips = {client.ip for client in clients}

    for client in clients:
        peer = peers.get(client.public_key)
        minion_url = f"http://{client.ip}:{config.minion_port}"
        statuses.append(
            DeviceStatus(
                name=client.name,
                ip=client.ip,
                address=client.address,
                public_key=client.public_key,
                config_path=client.config_path,
                interface=peer.interface if peer else None,
                endpoint=peer.endpoint if peer else None,
                latest_handshake=peer.latest_handshake if peer else None,
                transfer_rx=peer.transfer_rx if peer else None,
                transfer_tx=peer.transfer_tx if peer else None,
                wg_connected=_is_connected(peer, config.stale_after_seconds, now),
                pingable=ping_ip(client.ip),
                minion_available=minion_available(minion_url),
                minion_url=minion_url,
                last_checked_at=now,
            )
        )

    for node in config.topology_nodes():
        if node.expected_vpn_ip in client_ips or not _ip_in_subnets(
            node.expected_vpn_ip,
            config.device_subnets,
        ):
            continue
        minion_url = f"http://{node.expected_vpn_ip}:{config.minion_port}"
        statuses.append(
            DeviceStatus(
                name=node.name,
                ip=node.expected_vpn_ip,
                address=f"{node.expected_vpn_ip}/32",
                public_key="",
                config_path="deployment",
                interface="local" if node.expected_vpn_ip == config.deployment.head else None,
                endpoint=None,
                latest_handshake=None,
                transfer_rx=None,
                transfer_tx=None,
                wg_connected=node.expected_vpn_ip == config.deployment.head,
                pingable=ping_ip(node.expected_vpn_ip),
                minion_available=minion_available(minion_url),
                minion_url=minion_url,
                last_checked_at=now,
            )
        )
    return statuses


def store_device_statuses(db: Session, statuses: list[DeviceStatus]) -> None:
    seen_names = {status.name for status in statuses}
    stale_query = db.query(Device)
    if seen_names:
        stale_query = stale_query.filter(Device.name.not_in(seen_names))
    for stale_device in stale_query.all():
        db.delete(stale_device)

    for status in statuses:
        device = db.query(Device).filter(Device.name == status.name).one_or_none()
        if device is None:
            device = Device(
                name=status.name,
                ip=status.ip,
                address=status.address,
                public_key=status.public_key,
                config_path=status.config_path,
                minion_url=status.minion_url,
            )
            db.add(device)
        device.ip = status.ip
        device.address = status.address
        device.public_key = status.public_key
        device.config_path = status.config_path
        device.interface = status.interface
        device.endpoint = status.endpoint
        device.latest_handshake = status.latest_handshake
        device.transfer_rx = status.transfer_rx
        device.transfer_tx = status.transfer_tx
        device.wg_connected = status.wg_connected
        device.pingable = status.pingable
        device.minion_available = status.minion_available
        device.minion_url = status.minion_url
        device.last_checked_at = status.last_checked_at
    db.commit()


def refresh_device_inventory(config: AppConfig) -> None:
    from cozy_network_manager.app.db.session import SessionLocal

    statuses = scan_wireguard_clients(config)
    with SessionLocal() as db:
        store_device_statuses(db, statuses)


def device_inventory(db: Session) -> list[Device]:
    return sorted(db.query(Device).all(), key=lambda device: ip_address(device.ip))
