import asyncio
from types import SimpleNamespace

import httpx
import pytest

from cozy_network_manager.app.collectors import docker_web
from cozy_network_manager.app.collectors.docker_web import WebCandidate, web_candidates
from cozy_network_manager.app.config import AppConfig
from cozy_network_manager.app.schemas import PublicInterface, Snapshot
from cozy_network_manager.app.ui.templates import templates


def attrs(bindings, *, status="running"):
    return {"State": {"Status": status}, "NetworkSettings": {"Ports": bindings}}


def binding(port, address="0.0.0.0"):
    return {"HostIp": address, "HostPort": str(port)}


def test_hetzner_apps_public_links_and_duplicate_bindings():
    for name, port in [("finland-flashcards-study-1", 18743), ("fi-movies", 58000), ("movie-map", 7419)]:
        candidates = web_candidates(
            attrs({"8000/tcp": [binding(port), binding(port, "::"), binding(port)]}),
            name, "10.46.0.5", "fi.pushtaev.ru", "89.167.84.213",
        )
        assert candidates == [WebCandidate(name, "10.46.0.5", "fi.pushtaev.ru", port)]
        assert candidates[0].url("http") == f"http://fi.pushtaev.ru:{port}/"


def test_binding_filter_and_multiple_ports():
    candidates = web_candidates(attrs({
        "8000/tcp": [binding(8000), binding(8001, "10.46.0.5"), binding(8002, "89.167.84.213"),
                     binding(8003, "127.0.0.1"), binding(8004, "10.46.0.9"),
                     binding(8005, "::"), binding(8006, "::1"), binding(70000), binding("bad")],
        "5432/tcp": [binding(15432, "127.0.0.1")],
        "9000/udp": [binding(9000)], "9001/tcp": None,
    }), "app", "10.46.0.5", "fi.pushtaev.ru")
    assert [c.url("http") for c in candidates] == [
        "http://fi.pushtaev.ru:8000/", "http://10.46.0.5:8001/", "http://fi.pushtaev.ru:8002/",
    ]
    assert candidates[2].address == "89.167.84.213"
    assert web_candidates(attrs({"80/tcp": [binding(80)]}, status="exited"), "app", "10.46.0.5") == []


def test_public_address_and_vpn_fallbacks():
    data = attrs({"80/tcp": [binding(80)]})
    assert web_candidates(data, "app", "10.46.0.5", public_ipv4="89.167.84.213")[0].url("http") == "http://89.167.84.213/"
    assert web_candidates(data, "app", "10.46.0.5")[0].url("http") == "http://10.46.0.5/"
    assert web_candidates(data, "app", None) == []


@pytest.mark.parametrize("status", [200, 302, 401, 403, 404, 500, 503])
async def test_probe_response_status_and_no_redirect_following(status):
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(status, headers={"location": "https://elsewhere.example/"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), follow_redirects=False) as client:
        result = await docker_web._probe(client, WebCandidate("app", "10.46.0.5", "fi.pushtaev.ru", 18743))
    assert len(requests) == 1
    assert requests[0].url.host == "10.46.0.5"
    assert requests[0].headers["host"] == "fi.pushtaev.ru:18743"
    assert result.status == ("down" if status >= 500 else "up")


@pytest.mark.parametrize("port,schemes", [(8443, ["http", "https"]), (443, ["https"])])
async def test_https_discovery(port, schemes):
    seen = []
    def handle(request):
        seen.append(request.url.scheme)
        if request.url.scheme == "http":
            raise httpx.RemoteProtocolError("TLS required")
        return httpx.Response(200)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        result = await docker_web._probe(client, WebCandidate("app", "10.46.0.5", "fi.pushtaev.ru", port))
    assert seen == schemes
    assert result.url == ("https://fi.pushtaev.ru/" if port == 443 else "https://fi.pushtaev.ru:8443/")


async def test_non_http_service_is_omitted():
    def handle(request):
        raise httpx.RemoteProtocolError("not HTTP")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        assert await docker_web._probe(client, WebCandidate("database", "10.46.0.5", "10.46.0.5", 5432)) is None


async def test_request_timeout(monkeypatch):
    monkeypatch.setattr(docker_web, "REQUEST_TIMEOUT", 0.01)
    async def handle(request):
        await asyncio.sleep(1)
        return httpx.Response(200)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        assert await docker_web._probe(client, WebCandidate("slow", "10.46.0.5", "10.46.0.5", 80)) is None


async def test_budget_cancels_probes_preserves_results_and_limits_concurrency(monkeypatch):
    monkeypatch.setattr(docker_web, "DISCOVERY_BUDGET", 0.05)
    active = peak = 0
    async def probe(client, candidate):
        nonlocal active, peak
        if candidate.port == 80:
            return PublicInterface(service="fast", url=candidate.url("http"), status="up")
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(10)
        finally:
            active -= 1
    monkeypatch.setattr(docker_web, "_probe", probe)
    found, warnings = await docker_web.discover_web_interfaces([
        WebCandidate("app", "10.46.0.5", "10.46.0.5", port) for port in range(80, 100)
    ])
    assert len(found) == 1
    assert len(warnings) == 1
    assert peak == 8
    assert active == 0


def test_hostname_configuration_and_arbitrary_service_schema():
    assert AppConfig(public_hostnames={"10.46.0.5": "FI.Pushtaev.ru."}).public_hostnames == {"10.46.0.5": "fi.pushtaev.ru"}
    for invalid in ["http://fi.pushtaev.ru", "fi.pushtaev.ru:80", "fi.pushtaev.ru/path", "bad host"]:
        with pytest.raises(ValueError):
            AppConfig(public_hostnames={"10.46.0.5": invalid})
    interface = PublicInterface(service="finland-flashcards-study-1", url="http://fi.pushtaev.ru:18743/", status="up")
    assert Snapshot.model_validate({"node_name": "node", "public_interfaces": [interface.model_dump()]}).public_interfaces == [interface]
    with pytest.raises(ValueError):
        PublicInterface(service="", url="http://example.com/", status="up")


@pytest.mark.parametrize("template", ["dashboard.html", "node_detail.html"])
def test_both_tables_render_service_links_safely_and_stale(template):
    interface = {"service": "app<script>", "url": "http://fi.pushtaev.ru:18743/", "status": "up"}
    node = SimpleNamespace(name="10.46.0.5", expected_vpn_ip="10.46.0.5", os_override=None,
                           manual_tags=[], configured_tags=[], notes="")
    html = templates.env.get_template(template).render(
        request=SimpleNamespace(state=SimpleNamespace(auth_configured=False, authenticated=False)),
        node=node, nodes=[], devices=[], device_rows=[], device_subnets=[], warnings=[],
        device=None, snapshot=SimpleNamespace(collected_at="now", snapshot={"host": {}, "public_interfaces": [interface]}),
        snapshot_stale=True, sshfs_mount_rows=[], dns_records=[], forward_rows=[], bridge_projects=[],
        public_interface_rows=[{"node": node, **interface, "status": "stale"}],
    )
    assert 'href="http://fi.pushtaev.ru:18743/"' in html
    assert "app&lt;script&gt;" in html
    assert ">stale</span>" in html
