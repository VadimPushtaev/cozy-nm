from __future__ import annotations

import json
import platform
import socket
import subprocess
from pathlib import Path
from typing import Any

from cozy_network_manager.app.schemas import CollectorMessage, HostInfo


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return None


def _parse_os_release(text: str | None) -> tuple[str | None, str | None]:
    if not text:
        return None, None
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values.get("PRETTY_NAME") or values.get("NAME"), values.get("VERSION_ID")


def _uptime_seconds(host_root: Path) -> float | None:
    text = _read_text(host_root / "proc/uptime") or _read_text(Path("/proc/uptime"))
    if not text:
        return None
    try:
        return float(text.split()[0])
    except Exception:
        return None


def _ip_interfaces() -> tuple[list[dict[str, Any]], list[CollectorMessage]]:
    try:
        result = subprocess.run(
            ["ip", "-j", "addr"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except Exception as exc:
        return [], [CollectorMessage(source="host", message=f"cannot run ip addr: {exc}")]
    if result.returncode != 0:
        return [], [CollectorMessage(source="host", message=result.stderr.strip() or "ip addr failed")]
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return [], [CollectorMessage(source="host", message=f"cannot parse ip addr JSON: {exc}")]

    interfaces: list[dict[str, Any]] = []
    for item in data:
        interfaces.append(
            {
                "name": item.get("ifname"),
                "state": item.get("operstate"),
                "mac": item.get("address"),
                "addresses": [
                    {
                        "family": addr.get("family"),
                        "address": addr.get("local"),
                        "prefixlen": addr.get("prefixlen"),
                    }
                    for addr in item.get("addr_info", [])
                ],
            }
        )
    return interfaces, []


def collect_host(host_root: str = "/host") -> tuple[HostInfo, list[CollectorMessage]]:
    root = Path(host_root)
    hostname = _read_text(root / "etc/hostname") or socket.gethostname()
    os_name, os_version = _parse_os_release(
        _read_text(root / "etc/os-release") or _read_text(Path("/etc/os-release"))
    )
    interfaces, warnings = _ip_interfaces()
    return (
        HostInfo(
            hostname=hostname,
            os_name=os_name,
            os_version=os_version,
            kernel_version=platform.release(),
            architecture=platform.machine(),
            uptime_seconds=_uptime_seconds(root),
            interfaces=interfaces,
        ),
        warnings,
    )

