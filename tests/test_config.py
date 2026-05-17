from __future__ import annotations

from pathlib import Path

from cozy_network_manager.app.config import load_config


def test_load_config_and_env_override(tmp_path: Path, monkeypatch):
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        """
mode: head
node_name: head-one
listen_port: 9000
device_scan_interval_seconds: 10
wireguard_clients_path: /host/wireguard/clients
public_ipv4_url: https://ifconfig.me/ip
deployment:
  head: 10.0.0.1
  minions:
    - 10.0.0.1
    - 10.0.0.2
device_subnets:
  - 10.46.0.0/24
dns:
  domains: [example.com]
  hostnames: [vpn.example.com]
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("CNM_MODE", "minion")
    monkeypatch.setenv("CNM_LISTEN_PORT", "8081")

    config = load_config(config_path)

    assert config.mode == "minion"
    assert config.node_name == "head-one"
    assert config.listen_port == 8081
    assert config.device_scan_interval_seconds == 10
    assert config.wireguard_clients_path == "/host/wireguard/clients"
    assert config.public_ipv4_url == "https://ifconfig.me/ip"
    assert [(node.name, node.expected_vpn_ip) for node in config.topology_nodes()] == [
        ("10.0.0.1", "10.0.0.1"),
        ("10.0.0.2", "10.0.0.2"),
    ]
    assert config.minion_targets() == [
        ("10.0.0.1", "http://10.0.0.1:8000"),
        ("10.0.0.2", "http://10.0.0.2:8000"),
    ]
    assert config.device_subnets == ["10.46.0.0/24"]
    assert config.dns.hostnames == ["vpn.example.com"]
    assert config.dns_domains() == ["example.com"]
    assert config.dns_hostnames() == ["vpn.example.com"]
