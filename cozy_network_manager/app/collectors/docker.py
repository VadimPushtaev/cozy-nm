from __future__ import annotations

from ipaddress import IPv4Address

from cozy_network_manager.app.collectors.socat import (
    SOCAT_BRIDGE_ENV_KEYS,
    detect_socat_forwards,
    env_list_to_dict,
)
from cozy_network_manager.app.schemas import (
    CollectorMessage,
    DockerContainer,
    PublicInterface,
    SocatForward,
)


_JELLYFIN_HTTP_PORT = "8096/tcp"
_JELLYFIN_IMAGE_REPOSITORIES = {"jellyfin/jellyfin", "linuxserver/jellyfin"}
_WILDCARD_ADDRESSES = {"", "0.0.0.0", "::", "*"}


def _image_repository(image: str | None) -> str:
    if not image:
        return ""
    repository = image.lower().split("@", 1)[0]
    last_slash = repository.rfind("/")
    tag_separator = repository.rfind(":")
    if tag_separator > last_slash:
        repository = repository[:tag_separator]
    return repository


def _is_jellyfin_image(image: str | None) -> bool:
    repository = _image_repository(image)
    return any(
        repository == known or repository.endswith(f"/{known}")
        for known in _JELLYFIN_IMAGE_REPOSITORIES
    )


def _vpn_ipv4(node_ip: str | None) -> str | None:
    if not node_ip:
        return None
    try:
        return str(IPv4Address(node_ip))
    except ValueError:
        return None


def _jellyfin_http_ports(attrs: dict, node_ip: str) -> set[int]:
    host_config = attrs.get("HostConfig") or {}
    if host_config.get("NetworkMode") == "host":
        exposed = (attrs.get("Config") or {}).get("ExposedPorts") or {}
        return {8096} if _JELLYFIN_HTTP_PORT in exposed else set()

    ports = (attrs.get("NetworkSettings") or {}).get("Ports") or {}
    bindings = ports.get(_JELLYFIN_HTTP_PORT) or []
    host_ports: set[int] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        host_ip = str(binding.get("HostIp") or "")
        if host_ip not in {*_WILDCARD_ADDRESSES, node_ip}:
            continue
        try:
            host_port = int(binding.get("HostPort"))
        except (TypeError, ValueError):
            continue
        if 1 <= host_port <= 65535:
            host_ports.add(host_port)
    return host_ports


def detect_docker_public_interfaces(
    attrs: dict, node_ip: str | None
) -> list[PublicInterface]:
    vpn_ip = _vpn_ipv4(node_ip)
    config = attrs.get("Config") or {}
    state = attrs.get("State") or {}
    if vpn_ip is None or state.get("Status") != "running":
        return []
    if not _is_jellyfin_image(config.get("Image")):
        return []
    return [
        PublicInterface(
            service="jellyfin",
            url=f"http://{vpn_ip}{'' if port == 80 else f':{port}'}/",
            status="up",
        )
        for port in sorted(_jellyfin_http_ports(attrs, vpn_ip))
    ]


def collect_docker(
    node_ip: str | None = None,
) -> tuple[
    list[DockerContainer],
    list[SocatForward],
    list[PublicInterface],
    list[CollectorMessage],
]:
    try:
        import docker
    except Exception as exc:
        return [], [], [], [
            CollectorMessage(source="docker", message=f"docker SDK unavailable: {exc}")
        ]

    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
    except Exception as exc:
        return [], [], [], [
            CollectorMessage(source="docker", message=f"cannot inspect Docker: {exc}")
        ]

    collected: list[DockerContainer] = []
    interfaces: list[PublicInterface] = []
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
                    environment=env_list_to_dict(config.get("Env"), SOCAT_BRIDGE_ENV_KEYS),
                )
            )
            interfaces.extend(detect_docker_public_interfaces(attrs, node_ip))
        except Exception as exc:
            warnings.append(
                CollectorMessage(source="docker", message=f"failed to inspect container: {exc}")
            )
    interfaces = sorted(
        {(item.service, item.url): item for item in interfaces}.values(),
        key=lambda item: (item.service, item.url),
    )
    return collected, detect_socat_forwards(collected), interfaces, warnings
