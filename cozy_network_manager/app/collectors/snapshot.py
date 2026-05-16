from __future__ import annotations

from cozy_network_manager.app.collectors.docker import collect_docker
from cozy_network_manager.app.collectors.host import collect_host
from cozy_network_manager.app.collectors.wireguard import collect_wireguard
from cozy_network_manager.app.config import AppConfig
from cozy_network_manager.app.schemas import Snapshot


def collect_snapshot(config: AppConfig) -> Snapshot:
    warnings = []
    errors = []

    host, host_warnings = collect_host(config.host_root)
    warnings.extend(host_warnings)

    try:
        wireguard, wg_warnings = collect_wireguard(config.wireguard_interfaces)
        warnings.extend(wg_warnings)
    except Exception as exc:
        wireguard = []
        errors.append({"source": "wireguard", "message": str(exc)})

    try:
        containers, forwards, docker_warnings = collect_docker()
        warnings.extend(docker_warnings)
    except Exception as exc:
        containers = []
        forwards = []
        errors.append({"source": "docker", "message": str(exc)})

    return Snapshot(
        node_name=config.node_name,
        host=host,
        wireguard=wireguard,
        docker_containers=containers,
        socat_forwards=forwards,
        warnings=warnings,
        errors=errors,
    )

