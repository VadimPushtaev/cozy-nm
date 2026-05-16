from __future__ import annotations

from datetime import datetime, timezone

from cozy_network_manager.app.services.devices import extract_wireguard_devices


def test_extract_wireguard_devices_filters_to_device_subnet():
    snapshot = {
        "wireguard": [
            {
                "name": "wg0",
                "peers": [
                    {
                        "public_key": "peer-a",
                        "endpoint": "203.0.113.10:51820",
                        "allowed_ips": ["10.46.0.7/32", "10.8.0.7/32"],
                        "latest_handshake": 1_800_000_000,
                        "transfer_rx": 100,
                        "transfer_tx": 200,
                    }
                ],
            }
        ]
    }

    devices = extract_wireguard_devices(
        snapshot,
        source_node="cozy-head",
        subnets=["10.46.0.0/24"],
        stale_after_seconds=300,
        now=datetime.fromtimestamp(1_800_000_010, tz=timezone.utc),
    )

    assert len(devices) == 1
    assert devices[0].ip == "10.46.0.7"
    assert devices[0].allowed_ip == "10.46.0.7/32"
    assert devices[0].online is True
    assert devices[0].handshake_age_seconds == 10


def test_extract_wireguard_devices_marks_old_handshake_stale():
    snapshot = {
        "wireguard": [
            {
                "name": "wg0",
                "peers": [
                    {
                        "public_key": "peer-a",
                        "allowed_ips": ["10.46.0.8/32"],
                        "latest_handshake": 1_800_000_000,
                    }
                ],
            }
        ]
    }

    devices = extract_wireguard_devices(
        snapshot,
        source_node="cozy-head",
        subnets=["10.46.0.0/24"],
        stale_after_seconds=300,
        now=datetime.fromtimestamp(1_800_000_500, tz=timezone.utc),
    )

    assert devices[0].online is False
    assert devices[0].handshake_age_seconds == 500
