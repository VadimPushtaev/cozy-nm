from __future__ import annotations

from cozy_network_manager.app.services.dns import map_dns_answer


def test_dns_mapping_matches_known_node():
    mapping = map_dns_answer("nas.example.com", "A", "10.8.0.2", {"10.8.0.2": "nas"})

    assert mapping.matched_node == "nas"
    assert mapping.outside_vpn is False
    assert mapping.warning is None


def test_dns_mapping_warns_for_outside_vpn_ip():
    mapping = map_dns_answer("www.example.com", "A", "93.184.216.34", {"10.8.0.2": "nas"})

    assert mapping.matched_node is None
    assert mapping.outside_vpn is True
    assert "outside" in (mapping.warning or "")


def test_dns_cname_is_not_outside_vpn_warning():
    mapping = map_dns_answer("www.example.com", "CNAME", "target.example.com", {})

    assert mapping.outside_vpn is False

