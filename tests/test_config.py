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
known_nodes:
  - name: node-a
    expected_vpn_ip: 10.0.0.2
    minion_api_url: http://10.0.0.2:8000
    tags: [linux]
device_subnets:
  - 10.46.0.0/24
dns:
  hostnames: [node-a.example.com]
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("CNM_MODE", "minion")
    monkeypatch.setenv("CNM_LISTEN_PORT", "8081")

    config = load_config(config_path)

    assert config.mode == "minion"
    assert config.node_name == "head-one"
    assert config.listen_port == 8081
    assert config.known_nodes[0].name == "node-a"
    assert str(config.known_nodes[0].minion_api_url) == "http://10.0.0.2:8000/"
    assert config.device_subnets == ["10.46.0.0/24"]
    assert config.dns.hostnames == ["node-a.example.com"]
