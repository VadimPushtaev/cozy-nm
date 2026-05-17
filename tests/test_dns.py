from __future__ import annotations

from datetime import datetime, timezone

from cozy_network_manager.app.db.models import Device, Node, SnapshotRecord
from cozy_network_manager.app.services.dns import build_dns_ip_map, map_dns_answer


def test_dns_mapping_matches_known_node():
    mapping = map_dns_answer("nas.example.com", "A", "10.8.0.2", {"10.8.0.2": "nas"})

    assert mapping.matched_node == "nas"
    assert mapping.outside_vpn is False
    assert mapping.warning is None


def test_dns_mapping_warns_for_outside_vpn_ip():
    mapping = map_dns_answer("www.example.com", "A", "93.184.216.34", {"10.8.0.2": "nas"})

    assert mapping.matched_node is None
    assert mapping.outside_vpn is True
    assert "not seen" in (mapping.warning or "")


def test_dns_cname_is_not_outside_vpn_warning():
    mapping = map_dns_answer("www.example.com", "CNAME", "target.example.com", {})

    assert mapping.outside_vpn is False


def test_dns_mapping_matches_public_ipv4_from_latest_snapshot():
    node = Node(id=1, name="nas", expected_vpn_ip="10.8.0.2")
    node.snapshots = [
        SnapshotRecord(
            node_id=1,
            snapshot={"host": {"public_ipv4": "203.0.113.10"}},
            collected_at=datetime.now(timezone.utc),
        )
    ]

    mapping = map_dns_answer("nas.example.com", "A", "203.0.113.10", build_dns_ip_map([node]))

    assert mapping.matched_node == "nas"
    assert mapping.outside_vpn is False


def test_dns_mapping_matches_device_public_endpoint():
    device = Device(
        name="laptop",
        ip="10.46.0.6",
        address="10.46.0.6/32",
        public_key="public-key",
        config_path="/wireguard/clients/laptop.conf",
        endpoint="8.8.8.8:51820",
        minion_url="http://10.46.0.6:8000",
    )

    mapping = map_dns_answer("laptop.example.com", "A", "8.8.8.8", build_dns_ip_map([], [device]))

    assert mapping.matched_node == "laptop"
    assert mapping.outside_vpn is False
