from __future__ import annotations

import posixpath
from ipaddress import ip_address
from pathlib import PurePosixPath
from typing import Any


def _alias(value: str | None) -> str | None:
    normalized = (value or "").strip().rstrip(".").lower()
    return normalized or None


def _normalized_ip(value: str | None) -> str | None:
    try:
        return str(ip_address((value or "").strip().strip("[]")))
    except ValueError:
        return None


def _unique_aliases(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    candidates: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        node = entry["node"]
        values = {node.name, node.expected_vpn_ip}
        if entry.get("snapshot") and not entry.get("stale"):
            values.add((entry["snapshot"].get("host") or {}).get("hostname"))
        for value in values:
            alias = _alias(value)
            if alias:
                candidates.setdefault(alias, []).append(entry)
    return {
        alias: values[0]
        for alias, values in candidates.items()
        if len({item["node"].name for item in values}) == 1
    }


def _target_directory(chroot: str, remote_path: str) -> str | None:
    if not chroot.startswith("/") or not remote_path.startswith("/"):
        return None
    normalized_remote = posixpath.normpath("/" + remote_path.lstrip("/"))
    return posixpath.normpath(chroot.rstrip("/") + normalized_remote)


def _target_export(snapshot: dict, username: str | None, port: int):
    if not username:
        return None
    for export in snapshot.get("sftp_exports", []):
        if export.get("username") != username:
            continue
        if port not in export.get("ports", [22]):
            continue
        return export
    return None


def _windows_directory(snapshot: dict, target_directory: str | None) -> str | None:
    if not target_directory:
        return None
    target = PurePosixPath(target_directory)
    candidates = []
    for mapping in snapshot.get("windows_path_mappings", []):
        linux_value = mapping.get("linux_path")
        windows_value = mapping.get("windows_path")
        if not linux_value or not windows_value:
            continue
        linux_path = PurePosixPath(linux_value)
        if target == linux_path or target.is_relative_to(linux_path):
            candidates.append((len(linux_path.parts), linux_path, windows_value))
    if not candidates:
        return None
    _, linux_path, windows_path = max(candidates, key=lambda item: item[0])
    relative = target.relative_to(linux_path)
    if not relative.parts:
        return windows_path
    separator = "" if windows_path.endswith(("\\", "/")) else "\\"
    return windows_path + separator + "\\".join(relative.parts)


def correlate_sshfs_mounts(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    aliases = _unique_aliases(entries)
    rows: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for initiator in entries:
        snapshot = initiator.get("snapshot")
        if not snapshot or initiator.get("stale"):
            continue
        initiator_node = initiator["node"]
        initiator_ip = _normalized_ip(initiator_node.expected_vpn_ip) or initiator_node.name
        for mount in snapshot.get("sshfs_mounts", []):
            target_host = (mount.get("target_host") or "").strip().strip("[]")
            target_entry = aliases.get(_alias(target_host) or "")
            target_node = target_entry["node"] if target_entry else None
            target_ip = _normalized_ip(target_host)
            if target_node is not None:
                target_ip = _normalized_ip(target_node.expected_vpn_ip) or target_ip

            target_snapshot = None
            if target_entry and not target_entry.get("stale"):
                target_snapshot = target_entry.get("snapshot")
            target_directory = None
            windows_directory = None
            if target_snapshot:
                export = _target_export(
                    target_snapshot,
                    mount.get("username"),
                    int(mount.get("target_port", 22)),
                )
                if export:
                    target_directory = _target_directory(
                        export.get("chroot_directory", ""),
                        mount.get("remote_path", ""),
                    )
                    windows_directory = _windows_directory(target_snapshot, target_directory)

            initiator_directory = mount.get("local_path", "")
            key = (
                str(initiator_ip),
                target_ip or target_host,
                initiator_directory,
                target_directory or mount.get("remote_path", ""),
            )
            rows[key] = {
                "initiator_node": initiator_node,
                "target_node": target_node,
                "initiator_ip": initiator_ip,
                "target_ip": target_ip,
                "target_host": target_host,
                "initiator_directory": initiator_directory,
                "target_directory": target_directory,
                "windows_directory": windows_directory,
            }
    return [rows[key] for key in sorted(rows)]
