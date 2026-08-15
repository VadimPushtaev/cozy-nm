from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from cozy_network_manager.app.collectors.docker import (
    collect_docker,
    detect_docker_public_interfaces,
)
from cozy_network_manager.app.collectors.snapshot import _merge_public_interfaces
from cozy_network_manager.app.schemas import PublicInterface


def _attrs(
    *,
    image: str = "jellyfin/jellyfin:latest",
    status: str = "running",
    network_mode: str = "host",
    exposed_ports: dict | None = None,
    published_ports: dict | None = None,
) -> dict:
    return {
        "Config": {
            "Image": image,
            "ExposedPorts": exposed_ports
            if exposed_ports is not None
            else {"8096/tcp": {}},
        },
        "HostConfig": {"NetworkMode": network_mode},
        "NetworkSettings": {"Ports": published_ports or {}},
        "State": {"Status": status},
    }


@pytest.mark.parametrize(
    "image",
    [
        "jellyfin/jellyfin:latest",
        "registry.example/jellyfin/jellyfin@sha256:abcdef",
        "linuxserver/jellyfin:10.10.7",
        "lscr.io/linuxserver/jellyfin:latest",
    ],
)
def test_recognizes_known_jellyfin_images_in_host_network(image: str):
    interfaces = detect_docker_public_interfaces(_attrs(image=image), "10.46.0.6")

    assert [item.model_dump() for item in interfaces] == [
        {
            "service": "jellyfin",
            "url": "http://10.46.0.6:8096/",
            "status": "up",
        }
    ]


def test_docker_collection_returns_recognized_interfaces(monkeypatch):
    container = SimpleNamespace(
        short_id="abc123",
        name="jellyfin",
        status="running",
        attrs=_attrs(),
    )
    container_collection = SimpleNamespace(list=lambda *, all: [container])
    docker_module = SimpleNamespace(
        from_env=lambda: SimpleNamespace(containers=container_collection)
    )
    monkeypatch.setitem(sys.modules, "docker", docker_module)

    containers, forwards, interfaces, warnings = collect_docker("10.46.0.6")

    assert [item.name for item in containers] == ["jellyfin"]
    assert forwards == []
    assert [item.url for item in interfaces] == ["http://10.46.0.6:8096/"]
    assert warnings == []


def test_uses_docker_host_port_bindings_and_deduplicates_wildcards():
    interfaces = detect_docker_public_interfaces(
        _attrs(
            network_mode="bridge",
            published_ports={
                "8096/tcp": [
                    {"HostIp": "0.0.0.0", "HostPort": "18096"},
                    {"HostIp": "::", "HostPort": "18096"},
                    {"HostIp": "10.46.0.6", "HostPort": "28096"},
                    {"HostIp": "127.0.0.1", "HostPort": "38096"},
                    {"HostIp": "203.0.113.6", "HostPort": "48096"},
                ]
            },
        ),
        "10.46.0.6",
    )

    assert [item.url for item in interfaces] == [
        "http://10.46.0.6:18096/",
        "http://10.46.0.6:28096/",
    ]


@pytest.mark.parametrize(
    ("attrs", "node_ip"),
    [
        (_attrs(image="postgres:16"), "10.46.0.6"),
        (_attrs(status="exited"), "10.46.0.6"),
        (_attrs(exposed_ports={"8920/tcp": {}}), "10.46.0.6"),
        (_attrs(network_mode="bridge"), "10.46.0.6"),
        (_attrs(), None),
        (_attrs(), "not-an-ip"),
    ],
)
def test_ignores_unrecognized_or_unreachable_containers(attrs: dict, node_ip: str | None):
    assert detect_docker_public_interfaces(attrs, node_ip) == []


def test_ignores_https_and_invalid_http_bindings():
    interfaces = detect_docker_public_interfaces(
        _attrs(
            network_mode="bridge",
            published_ports={
                "8096/tcp": [
                    {"HostIp": "0.0.0.0", "HostPort": "invalid"},
                    {"HostIp": "0.0.0.0", "HostPort": "70000"},
                ],
                "8920/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8920"}],
            },
        ),
        "10.46.0.6",
    )

    assert interfaces == []


def test_merges_docker_and_configured_interfaces_with_up_status_winning():
    interfaces = _merge_public_interfaces(
        [
            PublicInterface(
                service="transmission",
                url="http://10.46.0.6:9091/transmission/web/",
                status="up",
            ),
            PublicInterface(
                service="jellyfin",
                url="http://10.46.0.6:8096/",
                status="down",
            ),
        ],
        [
            PublicInterface(
                service="jellyfin",
                url="http://10.46.0.6:8096/",
                status="up",
            )
        ],
    )

    assert [item.model_dump() for item in interfaces] == [
        {
            "service": "jellyfin",
            "url": "http://10.46.0.6:8096/",
            "status": "up",
        },
        {
            "service": "transmission",
            "url": "http://10.46.0.6:9091/transmission/web/",
            "status": "up",
        },
    ]
