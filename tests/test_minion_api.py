from __future__ import annotations

import pytest
from fastapi import HTTPException

from cozy_network_manager.app.config import AppConfig
from cozy_network_manager.app.config import clear_config_cache
from cozy_network_manager.app.api.minion import require_bridge_token, router


def test_minion_health(monkeypatch):
    monkeypatch.setenv("CNM_MODE", "minion")
    monkeypatch.setenv("CNM_NODE_NAME", "test-minion")
    clear_config_cache()
    monkeypatch.setattr(
        "cozy_network_manager.app.api.minion.collect_public_ipv4",
        lambda url: ("203.0.113.20", None),
    )

    health_route = next(route for route in router.routes if getattr(route, "path", None) == "/health")
    payload = health_route.endpoint()

    assert payload["status"] == "ok"
    assert payload["mode"] == "minion"
    assert payload["node_name"] == "test-minion"
    assert payload["public_ipv4"] == "203.0.113.20"
    assert payload["public_ipv4_error"] is None


def test_bridge_api_requires_configured_bearer_token(monkeypatch):
    monkeypatch.setattr(
        "cozy_network_manager.app.api.minion.get_config",
        lambda: AppConfig(mode="minion", bridge_api_token="expected"),
    )

    require_bridge_token("Bearer expected")
    with pytest.raises(HTTPException) as missing:
        require_bridge_token(None)
    with pytest.raises(HTTPException) as wrong:
        require_bridge_token("Bearer wrong")

    assert missing.value.status_code == 401
    assert wrong.value.status_code == 401


def test_bridge_api_is_not_exposed_by_head_mode(monkeypatch):
    monkeypatch.setattr(
        "cozy_network_manager.app.api.minion.get_config",
        lambda: AppConfig(mode="head", bridge_api_token="expected"),
    )

    with pytest.raises(HTTPException) as error:
        require_bridge_token("Bearer expected")

    assert error.value.status_code == 404


def test_bridge_routes_are_registered():
    registered = {
        (route.path, method)
        for route in router.routes
        for method in route.methods
        if route.path.startswith("/api/v1/bridges")
    }

    assert ("/api/v1/bridges", "GET") in registered
    assert ("/api/v1/bridges", "POST") in registered
    assert ("/api/v1/bridges/{name}", "PUT") in registered
    assert ("/api/v1/bridges/{name}", "DELETE") in registered
    assert ("/api/v1/bridges/project/apply", "POST") in registered
    assert ("/api/v1/bridges/project/restart", "POST") in registered
