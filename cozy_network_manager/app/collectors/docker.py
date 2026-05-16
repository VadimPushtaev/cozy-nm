from __future__ import annotations

from cozy_network_manager.app.collectors.socat import detect_socat_forwards, env_list_to_dict
from cozy_network_manager.app.schemas import CollectorMessage, DockerContainer, SocatForward


def collect_docker() -> tuple[list[DockerContainer], list[SocatForward], list[CollectorMessage]]:
    try:
        import docker
    except Exception as exc:
        return [], [], [CollectorMessage(source="docker", message=f"docker SDK unavailable: {exc}")]

    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
    except Exception as exc:
        return [], [], [CollectorMessage(source="docker", message=f"cannot inspect Docker: {exc}")]

    collected: list[DockerContainer] = []
    warnings: list[CollectorMessage] = []
    for container in containers:
        try:
            attrs = container.attrs
            config = attrs.get("Config") or {}
            network = attrs.get("NetworkSettings") or {}
            state = attrs.get("State") or {}
            collected.append(
                DockerContainer(
                    id=container.short_id,
                    name=container.name,
                    image=(attrs.get("Config") or {}).get("Image"),
                    status=state.get("Status") or container.status,
                    command=config.get("Cmd") or config.get("Entrypoint"),
                    published_ports=network.get("Ports") or {},
                    environment=env_list_to_dict(config.get("Env")),
                )
            )
        except Exception as exc:
            warnings.append(
                CollectorMessage(source="docker", message=f"failed to inspect container: {exc}")
            )
    return collected, detect_socat_forwards(collected), warnings

