from __future__ import annotations

import httpx

from cozy_network_manager.app.collectors.host import collect_public_ipv4


class _Response:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self) -> None:
        return None


def test_collect_public_ipv4(monkeypatch):
    def fake_get(url: str, timeout: int):
        assert url == "https://ifconfig.me/ip"
        assert timeout == 3
        return _Response("203.0.113.10\n")

    monkeypatch.setattr(httpx, "get", fake_get)

    public_ipv4, warning = collect_public_ipv4()

    assert public_ipv4 == "203.0.113.10"
    assert warning is None


def test_collect_public_ipv4_warns_on_invalid_response(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda url, timeout: _Response("not-an-ip"))

    public_ipv4, warning = collect_public_ipv4()

    assert public_ipv4 is None
    assert warning is not None
    assert warning.source == "public-ip"
