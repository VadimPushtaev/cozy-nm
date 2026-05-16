from __future__ import annotations

from cozy_network_manager.app.schemas import HostInfo, Snapshot, WireGuardInterface, WireGuardPeer


def test_snapshot_schema_serializes():
    snapshot = Snapshot(
        node_name="node-a",
        host=HostInfo(hostname="node-a", os_name="Linux"),
        wireguard=[
            WireGuardInterface(
                name="wg0",
                listen_port=51820,
                peers=[WireGuardPeer(public_key="peer", allowed_ips=["10.8.0.2/32"])],
            )
        ],
    )

    data = snapshot.model_dump(mode="json")

    assert data["node_name"] == "node-a"
    assert data["host"]["hostname"] == "node-a"
    assert data["wireguard"][0]["peers"][0]["allowed_ips"] == ["10.8.0.2/32"]
    assert data["timestamp"].endswith(("Z", "+00:00"))
