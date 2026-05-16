from __future__ import annotations

from pathlib import Path

from cozy_network_manager.app.services.devices import (
    load_client_configs,
    parse_client_config,
    parse_wg_peer_states,
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
