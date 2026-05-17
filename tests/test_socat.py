from __future__ import annotations

from cozy_network_manager.app.collectors.socat import detect_socat_forwards, infer_socat_forward
from cozy_network_manager.app.schemas import DockerContainer


def test_parse_socat_command_destination():
    container = DockerContainer(
        id="abc",
        name="socat-web",
        image="alpine/socat",
        status="running",
        command="socat TCP-LISTEN:8443,fork,reuseaddr TCP:10.8.0.5:443",
        published_ports={},
    )

    forward = infer_socat_forward(container)

    assert forward.source_port == 8443
    assert forward.destination_host == "10.8.0.5"
    assert forward.destination_port == 443


def test_detect_socat_and_fallback_source_port():
    container = DockerContainer(
        id="abc",
        name="forwarder",
        image="socat:latest",
        status="running",
        command="socat -d -d TCP-LISTEN:9000,fork -",
        published_ports={"9000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "19000"}]},
    )

    forwards = detect_socat_forwards([container])

    assert len(forwards) == 1
    assert forwards[0].source_port == 9000
    assert forwards[0].destination_host is None


def test_parse_socat_bridge_environment():
    container = DockerContainer(
        id="abc",
        name="bridge-15173",
        image="socat-bridge:latest",
        status="running",
        command=[
            "/bin/sh",
            "-c",
            "socat TCP-LISTEN:${LISTEN_PORT},reuseaddr,fork TCP:${TARGET_HOST}:${TARGET_PORT}",
        ],
        published_ports={"15173/tcp": [{"HostIp": "0.0.0.0", "HostPort": "15173"}]},
        environment={
            "LISTEN_PORT": "15173",
            "TARGET_HOST": "10.46.0.6",
            "TARGET_PORT": "15173",
        },
    )

    forward = infer_socat_forward(container)

    assert forward.source_port == 15173
    assert forward.destination_host == "10.46.0.6"
    assert forward.destination_port == 15173
