from __future__ import annotations

import json
from pathlib import Path

from cozy_network_manager.app.collectors.public_interfaces import collect_public_interfaces


def _write_proc(root: Path, processes: list[str], listeners: list[tuple[str, int]]) -> None:
    proc = root / "proc"
    for pid, process in enumerate(processes, start=1):
        process_dir = proc / str(pid)
        process_dir.mkdir(parents=True, exist_ok=True)
        (process_dir / "comm").write_text(process, encoding="utf-8")
    net = proc / "1/net"
    net.mkdir(parents=True, exist_ok=True)
    lines = ["  sl  local_address rem_address   st"]
    for index, (address, port) in enumerate(listeners):
        address_hex = "".join(f"{int(part):02X}" for part in reversed(address.split(".")))
        lines.append(
            f"{index}: {address_hex}:{port:04X} 00000000:0000 0A "
            "00000000:00000000 00:00000000 00000000 0 0 0"
        )
    (net / "tcp").write_text("\n".join(lines), encoding="utf-8")
    (net / "tcp6").write_text(lines[0], encoding="utf-8")


def _write_nginx(root: Path, site: str) -> None:
    nginx = root / "etc/nginx"
    (nginx / "sites-enabled").mkdir(parents=True)
    (nginx / "sites-available").mkdir()
    (nginx / "nginx.conf").write_text(
        "events {}\nhttp { include /etc/nginx/sites-enabled/*; }\n",
        encoding="utf-8",
    )
    (nginx / "sites-available/web").write_text(site, encoding="utf-8")
    (nginx / "sites-enabled/web").symlink_to("/etc/nginx/sites-available/web")


def _write_transmission(root: Path, **overrides) -> None:
    directory = root / "etc/transmission-daemon"
    directory.mkdir(parents=True, exist_ok=True)
    settings = {
        "rpc-enabled": True,
        "rpc-bind-address": "10.46.0.6",
        "rpc-port": 9091,
        "rpc-url": "/transmission/",
        "rpc-username": "secret-user",
        "rpc-password": "secret-password",
        **overrides,
    }
    (directory / "settings.json").write_text(json.dumps(settings), encoding="utf-8")


def test_collects_and_deduplicates_vpn_web_interfaces(tmp_path: Path):
    _write_nginx(
        tmp_path,
        """
        server { listen 80 default_server; server_name _; }
        server { listen 10.46.0.6:80; server_name files.example; }
        server { listen 443 ssl; server_name secure.example; }
        server { listen 203.0.113.20:8080; server_name public.example; }
        """,
    )
    _write_transmission(tmp_path)
    _write_proc(
        tmp_path,
        ["systemd", "nginx", "transmission-da"],
        [("0.0.0.0", 80), ("0.0.0.0", 443), ("10.46.0.6", 9091)],
    )

    interfaces, warnings = collect_public_interfaces(str(tmp_path), "10.46.0.6")

    assert [item.model_dump() for item in interfaces] == [
        {"service": "nginx", "url": "http://10.46.0.6/", "status": "up"},
        {"service": "nginx", "url": "https://10.46.0.6/", "status": "up"},
        {"service": "nginx", "url": "https://secure.example/", "status": "up"},
        {
            "service": "transmission",
            "url": "http://10.46.0.6:9091/transmission/web/",
            "status": "up",
        },
    ]
    assert warnings == []
    assert "secret" not in repr(interfaces)


def test_collects_named_sites_bound_to_public_addresses(tmp_path: Path):
    _write_nginx(
        tmp_path,
        """
        server {
            listen 93.184.216.34:80;
            server_name FILES.example.com. mirror.example.com *.example.com _;
        }
        server {
            listen 93.184.216.34:443 ssl;
            server_name secure.example.com;
        }
        server {
            listen 10.46.0.6:8080;
            server_name internal.example.com;
        }
        """,
    )
    _write_proc(
        tmp_path,
        ["systemd", "nginx"],
        [("93.184.216.34", 80), ("10.46.0.6", 8080)],
    )

    interfaces, warnings = collect_public_interfaces(str(tmp_path), "10.46.0.6")

    assert [(item.url, item.status) for item in interfaces] == [
        ("http://10.46.0.6:8080/", "up"),
        ("http://files.example.com/", "up"),
        ("http://mirror.example.com/", "up"),
        ("https://secure.example.com/", "down"),
    ]
    assert warnings == []


def test_configured_interfaces_remain_visible_when_services_are_down(tmp_path: Path):
    _write_nginx(tmp_path, "server { listen 10.46.0.1:9046; }")
    _write_transmission(tmp_path, **{"rpc-bind-address": "0.0.0.0"})
    _write_proc(tmp_path, ["systemd"], [])

    interfaces, warnings = collect_public_interfaces(str(tmp_path), "10.46.0.1")

    assert [(item.url, item.status) for item in interfaces] == [
        ("http://10.46.0.1:9046/", "down"),
        ("http://10.46.0.1:9091/transmission/web/", "down"),
    ]
    assert warnings == []


def test_ignores_disabled_or_non_vpn_transmission_rpc(tmp_path: Path):
    _write_transmission(tmp_path, **{"rpc-enabled": False})
    _write_proc(tmp_path, ["systemd", "transmission-da"], [("0.0.0.0", 9091)])

    disabled, disabled_warnings = collect_public_interfaces(str(tmp_path), "10.46.0.6")

    _write_transmission(
        tmp_path,
        **{"rpc-enabled": True, "rpc-bind-address": "203.0.113.20"},
    )
    public_only, public_warnings = collect_public_interfaces(str(tmp_path), "10.46.0.6")

    assert disabled == []
    assert public_only == []
    assert disabled_warnings == []
    assert public_warnings == []


def test_transmission_web_url_uses_custom_rpc_prefix(tmp_path: Path):
    _write_transmission(tmp_path, **{"rpc-url": "/torrent/"})
    _write_proc(tmp_path, ["systemd", "transmission-da"], [("10.46.0.6", 9091)])

    interfaces, warnings = collect_public_interfaces(str(tmp_path), "10.46.0.6")

    assert [item.url for item in interfaces] == [
        "http://10.46.0.6:9091/torrent/web/"
    ]
    assert warnings == []


def test_malformed_service_config_becomes_sanitized_warning(tmp_path: Path):
    transmission = tmp_path / "etc/transmission-daemon"
    transmission.mkdir(parents=True)
    (transmission / "settings.json").write_text('{"rpc-password": "do-not-report"', encoding="utf-8")
    _write_proc(tmp_path, ["systemd"], [])

    interfaces, warnings = collect_public_interfaces(str(tmp_path), "10.46.0.6")

    assert interfaces == []
    assert len(warnings) == 1
    assert warnings[0].source == "public-interfaces"
    assert "Transmission" in warnings[0].message
    assert "do-not-report" not in warnings[0].message


def test_ignores_external_nginx_module_symlinks(tmp_path: Path):
    nginx = tmp_path / "etc/nginx"
    (nginx / "modules-enabled").mkdir(parents=True)
    (nginx / "nginx.conf").write_text(
        "include /etc/nginx/modules-enabled/*.conf; events {}\n",
        encoding="utf-8",
    )
    (nginx / "modules-enabled/50-module.conf").symlink_to(
        "/usr/share/nginx/modules-available/module.conf"
    )
    _write_proc(tmp_path, ["systemd"], [])

    interfaces, warnings = collect_public_interfaces(str(tmp_path), "10.46.0.6")

    assert interfaces == []
    assert warnings == []


def test_requires_a_valid_ipv4_node_identity(tmp_path: Path):
    interfaces, warnings = collect_public_interfaces(str(tmp_path), "not-an-ip")

    assert interfaces == []
    assert [warning.source for warning in warnings] == ["public-interfaces"]
