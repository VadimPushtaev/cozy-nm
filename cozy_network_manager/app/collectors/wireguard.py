from __future__ import annotations

import shutil
import subprocess

from cozy_network_manager.app.schemas import CollectorMessage, WireGuardInterface, WireGuardPeer


def _to_int(value: str) -> int | None:
    if value in {"", "(none)", "off"}:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_wg_dump(output: str, interface_filter: list[str] | None = None) -> list[WireGuardInterface]:
    filters = set(interface_filter or [])
    interfaces: dict[str, WireGuardInterface] = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) == 5:
            name, _private_key, public_key, listen_port, _fwmark = parts
            if filters and name not in filters:
                continue
            interfaces[name] = WireGuardInterface(
                name=name,
                public_key=None if public_key == "(none)" else public_key,
                listen_port=_to_int(listen_port),
            )
            continue
        if len(parts) == 9:
            (
                name,
                public_key,
                _preshared_key,
                endpoint,
                allowed_ips,
                latest_handshake,
                transfer_rx,
                transfer_tx,
                _persistent_keepalive,
            ) = parts
            if filters and name not in filters:
                continue
            interface = interfaces.setdefault(name, WireGuardInterface(name=name))
            interface.peers.append(
                WireGuardPeer(
                    public_key=public_key,
                    endpoint=None if endpoint == "(none)" else endpoint,
                    allowed_ips=[] if allowed_ips == "(none)" else allowed_ips.split(","),
                    latest_handshake=_to_int(latest_handshake),
                    transfer_rx=_to_int(transfer_rx),
                    transfer_tx=_to_int(transfer_tx),
                )
            )
    return list(interfaces.values())


def collect_wireguard(
    interface_filter: list[str] | None = None,
) -> tuple[list[WireGuardInterface], list[CollectorMessage]]:
    if not shutil.which("wg"):
        return [], [CollectorMessage(source="wireguard", message="wg command not found")]
    try:
        result = subprocess.run(
            ["wg", "show", "all", "dump"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except Exception as exc:
        return [], [CollectorMessage(source="wireguard", message=f"wg failed: {exc}")]
    if result.returncode != 0:
        message = result.stderr.strip() or f"wg exited with status {result.returncode}"
        return [], [CollectorMessage(source="wireguard", message=message)]
    return parse_wg_dump(result.stdout, interface_filter), []

