from __future__ import annotations

import re
import shlex
from typing import Any

from cozy_network_manager.app.schemas import DockerContainer, SocatForward


DEST_PATTERNS = [
    re.compile(r"(?:tcp|tcp4|tcp6|tcp-connect|connect):([^:,\s]+):(\d+)", re.IGNORECASE),
    re.compile(r"([^:,\s]+):(\d+)$"),
]
LISTEN_PATTERN = re.compile(r"(?:tcp|tcp4|tcp6)-listen:(\d+)", re.IGNORECASE)
SOCAT_BRIDGE_ENV_KEYS = {"LISTEN_PORT", "TARGET_HOST", "TARGET_PORT"}


def _command_text(command: str | list[str] | None) -> str:
    if command is None:
        return ""
    if isinstance(command, list):
        return " ".join(str(part) for part in command)
    return command


def is_likely_socat(container: DockerContainer) -> bool:
    text = " ".join(
        [
            container.name or "",
            container.image or "",
            _command_text(container.command),
        ]
    ).lower()
    return "socat" in text


def _env_int(environment: dict[str, str], key: str) -> int | None:
    value = environment.get(key)
    if value is None or not value.isdigit():
        return None
    return int(value)


def infer_socat_forward(container: DockerContainer) -> SocatForward:
    command = _command_text(container.command)
    tokens = shlex.split(command) if command else []
    source_port = _env_int(container.environment, "LISTEN_PORT")
    destination_host = container.environment.get("TARGET_HOST")
    destination_port = _env_int(container.environment, "TARGET_PORT")

    for token in tokens:
        listen_match = LISTEN_PATTERN.search(token)
        if listen_match and source_port is None:
            source_port = int(listen_match.group(1))
        for pattern in DEST_PATTERNS:
            match = pattern.search(token)
            if match and "listen" not in token.lower() and destination_host is None:
                destination_host = match.group(1)
                destination_port = int(match.group(2))

    if source_port is None:
        for _container_port, bindings in container.published_ports.items():
            if not bindings:
                continue
            if isinstance(bindings, list) and bindings:
                host_port = bindings[0].get("HostPort")
                if host_port and host_port.isdigit():
                    source_port = int(host_port)
                    break

    return SocatForward(
        container_name=container.name,
        image=container.image,
        status=container.status,
        command=container.command,
        published_ports=container.published_ports,
        environment=container.environment,
        source_port=source_port,
        destination_host=destination_host,
        destination_port=destination_port,
    )


def detect_socat_forwards(containers: list[DockerContainer]) -> list[SocatForward]:
    return [infer_socat_forward(container) for container in containers if is_likely_socat(container)]


def env_list_to_dict(
    env: list[str] | dict[str, Any] | None, allowed_keys: set[str] | None = None
) -> dict[str, str]:
    if not env:
        return {}
    if isinstance(env, dict):
        return {
            str(key): str(value)
            for key, value in env.items()
            if allowed_keys is None or str(key) in allowed_keys
        }
    result: dict[str, str] = {}
    for item in env:
        if "=" in item:
            key, value = item.split("=", 1)
            if allowed_keys is None or key in allowed_keys:
                result[key] = value
    return result
