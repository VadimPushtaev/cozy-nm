from __future__ import annotations

import httpx
import pytest

from cozy_network_manager.app.config import (
    AppConfig,
    BridgeHostConfig,
    BridgeManagementConfig,
)
from cozy_network_manager.app.services.bridge_client import (
    BridgeClientError,
    bridge_request,
    fetch_bridge_projects,
)


def _config() -> AppConfig:
    return AppConfig(
        bridge_api_token="secret-token",
        minion_port=18081,
        bridges=BridgeManagementConfig(
            hosts=[
                BridgeHostConfig(node_ip="10.46.0.1", compose_dir="/root/socat-docker"),
                BridgeHostConfig(node_ip="10.46.0.5", compose_dir="/root/socat-docker"),
            ]
        ),
    )


def test_bridge_request_uses_whitelist_and_bearer_token(monkeypatch):
    captured = {}

    def request(method, url, **kwargs):
        captured.update(method=method, url=url, **kwargs)
        return httpx.Response(200, json={"node_ip": "10.46.0.1"})

    monkeypatch.setattr("cozy_network_manager.app.services.bridge_client.httpx.request", request)

    result = bridge_request(_config(), "10.46.0.1", "GET", "/api/v1/bridges")

    assert result["node_ip"] == "10.46.0.1"
    assert captured["url"] == "http://10.46.0.1:18081/api/v1/bridges"
    assert captured["headers"] == {"Authorization": "Bearer secret-token"}


def test_bridge_request_rejects_non_whitelisted_host():
    with pytest.raises(BridgeClientError, match="not whitelisted"):
        bridge_request(_config(), "10.46.0.99", "GET", "/api/v1/bridges")


def test_fetch_projects_keeps_unavailable_host_visible(monkeypatch):
    def request(method, url, **kwargs):
        if "10.46.0.5" in url:
            raise httpx.ConnectError("offline")
        return httpx.Response(
            200,
            json={
                "node_ip": "10.46.0.1",
                "compose_dir": "/root/socat-docker",
                "compose_file": "docker-compose.yml",
                "services": [],
                "orphans": [],
                "errors": [],
            },
        )

    monkeypatch.setattr("cozy_network_manager.app.services.bridge_client.httpx.request", request)

    projects = fetch_bridge_projects(_config())

    assert [project["node_ip"] for project in projects] == ["10.46.0.1", "10.46.0.5"]
    assert projects[0]["available"] is True
    assert projects[1]["available"] is False
    assert "Cannot reach" in projects[1]["errors"][0]
