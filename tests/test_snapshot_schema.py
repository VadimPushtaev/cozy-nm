from __future__ import annotations

from cozy_network_manager.app.schemas import (
    HostInfo,
    PublicInterface,
    Snapshot,
    WireGuardInterface,
    WireGuardPeer,
)


def test_snapshot_schema_serializes():
    snapshot = Snapshot(
        node_name="node-a",
        host=HostInfo(hostname="node-a", public_ipv4="203.0.113.10", os_name="Linux"),
        wireguard=[
            WireGuardInterface(
                name="wg0",
                listen_port=51820,
                peers=[WireGuardPeer(public_key="peer", allowed_ips=["10.8.0.2/32"])],
            )
        ],
        public_interfaces=[
            PublicInterface(
                service="nginx",
                url="http://10.8.0.1/",
                status="up",
            )
        ],
    )

    data = snapshot.model_dump(mode="json")

    assert data["node_name"] == "node-a"
    assert data["host"]["hostname"] == "node-a"
    assert data["host"]["public_ipv4"] == "203.0.113.10"
    assert data["wireguard"][0]["peers"][0]["allowed_ips"] == ["10.8.0.2/32"]
    assert data["public_interfaces"] == [
        {"service": "nginx", "url": "http://10.8.0.1/", "status": "up"}
    ]
    assert data["timestamp"].endswith(("Z", "+00:00"))


def test_old_snapshot_payload_defaults_public_interfaces_to_empty():
    snapshot = Snapshot.model_validate({"node_name": "old-minion"})

    assert snapshot.public_interfaces == []
