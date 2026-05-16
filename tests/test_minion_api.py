from __future__ import annotations

from cozy_network_manager.app.config import clear_config_cache
from cozy_network_manager.app.api.minion import router


def test_minion_health(monkeypatch):
    monkeypatch.setenv("CNM_MODE", "minion")
    monkeypatch.setenv("CNM_NODE_NAME", "test-minion")
    clear_config_cache()

    health_route = next(route for route in router.routes if getattr(route, "path", None) == "/health")
    payload = health_route.endpoint()

    assert payload["status"] == "ok"
    assert payload["mode"] == "minion"
    assert payload["node_name"] == "test-minion"
