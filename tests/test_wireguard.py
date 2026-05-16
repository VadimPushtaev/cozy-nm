from __future__ import annotations

from cozy_network_manager.app.collectors.wireguard import parse_wg_dump


def test_parse_wg_dump_interfaces_and_peers():
    dump = "\n".join(
        [
            "wg0\tpriv\tpub-interface\t51820\toff",
            "wg0\tpeer-public\t(none)\t1.2.3.4:51820\t10.8.0.2/32,fd00::2/128\t1710000000\t120\t240\toff",
        ]
    )

    interfaces = parse_wg_dump(dump)

    assert len(interfaces) == 1
    assert interfaces[0].name == "wg0"
    assert interfaces[0].listen_port == 51820
    assert interfaces[0].peers[0].allowed_ips == ["10.8.0.2/32", "fd00::2/128"]
    assert interfaces[0].peers[0].transfer_rx == 120


def test_parse_wg_dump_filter_and_missing_values():
    dump = "\n".join(
        [
            "wg0\tpriv\tpub-interface\t51820\toff",
            "wg1\tpriv\t(none)\t(none)\toff",
            "wg1\tpeer-public\t(none)\t(none)\t(none)\t0\t0\t0\toff",
        ]
    )

    interfaces = parse_wg_dump(dump, ["wg1"])

    assert [iface.name for iface in interfaces] == ["wg1"]
    assert interfaces[0].public_key is None
    assert interfaces[0].listen_port is None
    assert interfaces[0].peers[0].allowed_ips == []

