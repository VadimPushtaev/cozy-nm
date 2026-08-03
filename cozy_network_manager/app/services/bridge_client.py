from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import httpx

from cozy_network_manager.app.config import AppConfig, BridgeHostConfig


class BridgeClientError(RuntimeError):
    pass


def _headers(config: AppConfig) -> dict[str, str]:
    if not config.bridge_api_token:
        raise BridgeClientError("Bridge management token is not configured on the head.")
    return {"Authorization": f"Bearer {config.bridge_api_token}"}


def _host(config: AppConfig, node_ip: str) -> BridgeHostConfig:
    host = config.bridge_host(node_ip)
    if host is None:
        raise BridgeClientError(f"Node is not whitelisted for bridge management: {node_ip}")
    return host


def _error_message(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail")
    except Exception:
        detail = None
    if isinstance(detail, dict):
        return str(detail.get("message") or detail)
    return str(detail or response.text or f"HTTP {response.status_code}")


def bridge_request(
    config: AppConfig,
    node_ip: str,
    method: str,
    path: str,
    *,
    payload: dict | None = None,
    timeout: float = 10,
) -> dict:
    _host(config, node_ip)
    url = f"http://{node_ip}:{config.minion_port}{path}"
    try:
        response = httpx.request(
            method,
            url,
            headers=_headers(config),
            json=payload,
            timeout=timeout,
        )
    except Exception as exc:
        raise BridgeClientError(f"Cannot reach bridge minion {node_ip}: {exc}") from exc
    if response.status_code >= 400:
        raise BridgeClientError(f"Bridge minion {node_ip}: {_error_message(response)}")
    try:
        return response.json()
    except Exception as exc:
        raise BridgeClientError(f"Bridge minion {node_ip} returned invalid JSON.") from exc


def _fetch_project(config: AppConfig, host: BridgeHostConfig) -> dict:
    try:
        project = bridge_request(config, host.node_ip, "GET", "/api/v1/bridges", timeout=5)
        project["available"] = True
        return project
    except BridgeClientError as exc:
        return {
            "node_ip": host.node_ip,
            "compose_dir": host.compose_dir,
            "compose_file": host.compose_file,
            "compose_valid": False,
            "pending_apply": False,
            "services": [],
            "orphans": [],
            "errors": [str(exc)],
            "available": False,
        }


def fetch_bridge_projects(config: AppConfig) -> list[dict]:
    hosts = config.bridges.hosts
    if not hosts:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(hosts))) as executor:
        futures = [executor.submit(_fetch_project, config, host) for host in hosts]
        return [future.result() for future in futures]


def create_bridge(config: AppConfig, node_ip: str, payload: dict) -> dict:
    return bridge_request(config, node_ip, "POST", "/api/v1/bridges", payload=payload)


def update_bridge(config: AppConfig, node_ip: str, name: str, payload: dict) -> dict:
    return bridge_request(
        config,
        node_ip,
        "PUT",
        f"/api/v1/bridges/{quote(name, safe='')}",
        payload=payload,
    )


def delete_bridge(config: AppConfig, node_ip: str, name: str) -> dict:
    return bridge_request(
        config,
        node_ip,
        "DELETE",
        f"/api/v1/bridges/{quote(name, safe='')}",
    )


def bridge_action(config: AppConfig, node_ip: str, name: str, action: str) -> dict:
    return bridge_request(
        config,
        node_ip,
        "POST",
        f"/api/v1/bridges/{quote(name, safe='')}/actions/{quote(action, safe='')}",
        timeout=90,
    )


def project_action(config: AppConfig, node_ip: str, action: str) -> dict:
    timeout = 330 if action == "apply" else 150
    return bridge_request(
        config,
        node_ip,
        "POST",
        f"/api/v1/bridges/project/{quote(action, safe='')}",
        timeout=timeout,
    )
