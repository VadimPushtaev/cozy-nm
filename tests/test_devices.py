from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from cozy_network_manager.app.config import AppConfig, DeploymentConfig
from cozy_network_manager.app.db.models import Device, Node
from cozy_network_manager.app.db.session import Base
from cozy_network_manager.app.services.devices import (
    DeviceStatus,
    load_client_configs,
    parse_client_config,
    parse_wg_peer_states,
    scan_wireguard_clients,
    store_device_statuses,
)


def _write_client(path: Path, name: str, address: str, public_key: str = "pub-key") -> Path:
    config_path = path / f"{name}.conf"
    config_path.write_text(
        f"""
[Interface]
PrivateKey = secret
Address = {address}

[Peer]
PublicKey = server-key
AllowedIPs = 10.46.0.0/24
""",
        encoding="utf-8",
    )
    config_path.with_suffix(".pub").write_text(public_key, encoding="utf-8")
    return config_path


def test_parse_client_config_reads_address_and_public_key(tmp_path: Path):
    config_path = _write_client(tmp_path, "katja-macbook", "10.46.0.4/32", "client-pub")

    client = parse_client_config(config_path, ["10.46.0.0/24"])

    assert client is not None
    assert client.name == "katja-macbook"
    assert client.ip == "10.46.0.4"
    assert client.address == "10.46.0.4/32"
    assert client.public_key == "client-pub"


def test_load_client_configs_filters_to_device_subnet(tmp_path: Path):
    _write_client(tmp_path, "inside", "10.46.0.5/32")
    _write_client(tmp_path, "outside", "10.8.0.5/32")

    clients = load_client_configs(str(tmp_path), ["10.46.0.0/24"])

    assert [client.name for client in clients] == ["inside"]


def test_parse_wg_peer_states_uses_public_key():
    dump = "\n".join(
        [
            "wg0\tpriv\tpub-interface\t51820\toff",
            "wg0\tclient-pub\t(none)\t1.2.3.4:51820\t10.46.0.4/32\t1710000000\t120\t240\toff",
        ]
    )

    peers = parse_wg_peer_states(dump)

    assert peers["client-pub"].interface == "wg0"
    assert peers["client-pub"].endpoint == "1.2.3.4:51820"
    assert peers["client-pub"].latest_handshake == 1710000000
    assert peers["client-pub"].transfer_rx == 120


def test_device_public_ip_comes_from_endpoint_host():
    device = Device(
        name="client",
        ip="10.46.0.6",
        address="10.46.0.6/32",
        public_key="client-pub",
        config_path="/wireguard/clients/client.conf",
        endpoint="8.8.8.8:51820",
        minion_url="http://10.46.0.6:8000",
    )

    assert device.public_ip == "8.8.8.8"
    assert device.current_public_ip is None
    device.wg_connected = True
    assert device.current_public_ip == "8.8.8.8"


def test_device_public_ip_ignores_private_endpoint_host():
    device = Device(
        name="client",
        ip="10.46.0.6",
        address="10.46.0.6/32",
        public_key="client-pub",
        config_path="/wireguard/clients/client.conf",
        endpoint="192.168.1.20:51820",
        minion_url="http://10.46.0.6:8000",
    )

    assert device.public_ip is None


def test_scan_wireguard_clients_includes_deployment_head(monkeypatch):
    monkeypatch.setattr("cozy_network_manager.app.services.devices.load_client_configs", lambda *_: [])
    monkeypatch.setattr("cozy_network_manager.app.services.devices.load_wg_peer_states", lambda: {})
    monkeypatch.setattr("cozy_network_manager.app.services.devices.ping_ip", lambda ip: ip == "10.46.0.1")
    monkeypatch.setattr(
        "cozy_network_manager.app.services.devices.minion_available",
        lambda url: url == "http://10.46.0.1:18081",
    )

    statuses = scan_wireguard_clients(
        AppConfig(
            device_subnets=["10.46.0.0/24"],
            minion_port=18081,
            deployment=DeploymentConfig(head="10.46.0.1", minions=["10.46.0.1"]),
        )
    )

    assert len(statuses) == 1
    assert statuses[0].name == "10.46.0.1"
    assert statuses[0].ip == "10.46.0.1"
    assert statuses[0].wg_connected is True
    assert statuses[0].pingable is True
    assert statuses[0].minion_available is True


def test_scan_wireguard_clients_does_not_duplicate_configured_clients(monkeypatch, tmp_path):
    _write_client(tmp_path, "ubuntu", "10.46.0.5/32", "client-pub")
    client = load_client_configs(str(tmp_path), ["10.46.0.0/24"])[0]

    monkeypatch.setattr("cozy_network_manager.app.services.devices.load_client_configs", lambda *_: [client])
    monkeypatch.setattr("cozy_network_manager.app.services.devices.load_wg_peer_states", lambda: {})
    monkeypatch.setattr("cozy_network_manager.app.services.devices.ping_ip", lambda ip: False)
    monkeypatch.setattr("cozy_network_manager.app.services.devices.minion_available", lambda url: False)

    statuses = scan_wireguard_clients(
        AppConfig(
            device_subnets=["10.46.0.0/24"],
            deployment=DeploymentConfig(head="10.46.0.1", minions=["10.46.0.1", "10.46.0.5"]),
        )
    )

    assert [(status.name, status.ip) for status in statuses] == [
        ("ubuntu", "10.46.0.5"),
        ("10.46.0.1", "10.46.0.1"),
    ]


def test_store_device_statuses_creates_nodes_and_reuses_configured_ips():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    statuses = [
        DeviceStatus(
            name="ruvps",
            ip="10.46.0.1",
            address="10.46.0.1/32",
            public_key="one",
            config_path="one.conf",
            interface="wg0",
            endpoint=None,
            latest_handshake=None,
            transfer_rx=None,
            transfer_tx=None,
            wg_connected=True,
            pingable=True,
            minion_available=True,
            minion_url="http://10.46.0.1:18081",
            last_checked_at=now,
        ),
        DeviceStatus(
            name="phone",
            ip="10.46.0.8",
            address="10.46.0.8/32",
            public_key="eight",
            config_path="phone.conf",
            interface="wg0",
            endpoint=None,
            latest_handshake=None,
            transfer_rx=None,
            transfer_tx=None,
            wg_connected=False,
            pingable=False,
            minion_available=False,
            minion_url="http://10.46.0.8:18081",
            last_checked_at=now,
        ),
    ]

    with Session(engine) as db:
        db.add(Node(name="head", expected_vpn_ip="10.46.0.1"))
        db.commit()
        store_device_statuses(db, statuses)
        nodes = db.query(Node).order_by(Node.expected_vpn_ip).all()

    assert [(node.name, node.expected_vpn_ip) for node in nodes] == [
        ("head", "10.46.0.1"),
        ("phone", "10.46.0.8"),
    ]
