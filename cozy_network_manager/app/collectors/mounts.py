from __future__ import annotations

import glob
import re
import shlex
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from cozy_network_manager.app.schemas import (
    CollectorMessage,
    SftpExport,
    SshfsMount,
    WindowsPathMapping,
)


_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")
_WINDOWS_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")


@dataclass(frozen=True)
class _MountInfo:
    root: str
    mount_point: str
    filesystem_type: str
    source: str
    mount_options: tuple[str, ...]
    super_options: tuple[str, ...]


class _ExternalSshPath(ValueError):
    pass


def _unescape_mount_value(value: str) -> str:
    return _MOUNT_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _parse_mountinfo(text: str) -> tuple[list[_MountInfo], list[CollectorMessage]]:
    mounts: list[_MountInfo] = []
    warnings: list[CollectorMessage] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        columns = line.split()
        try:
            separator = columns.index("-")
            if separator < 6 or len(columns) < separator + 4:
                raise ValueError("not enough fields")
            mounts.append(
                _MountInfo(
                    root=_unescape_mount_value(columns[3]),
                    mount_point=_unescape_mount_value(columns[4]),
                    mount_options=tuple(columns[5].split(",")),
                    filesystem_type=columns[separator + 1],
                    source=_unescape_mount_value(columns[separator + 2]),
                    super_options=tuple(columns[separator + 3].split(",")),
                )
            )
        except (ValueError, IndexError) as exc:
            warnings.append(
                CollectorMessage(
                    source="mounts",
                    message=f"cannot parse host mount record {line_number}: {exc}",
                )
            )
    return mounts, warnings


def _sshfs_source(value: str) -> tuple[str | None, str, str] | None:
    if value.startswith("sshfs#"):
        value = value.removeprefix("sshfs#")
    bracketed = re.fullmatch(r"(?:(?P<user>[^@]+)@)?\[(?P<host>[^]]+)]:(?P<path>.*)", value)
    match = bracketed or re.fullmatch(
        r"(?:(?P<user>[^@:/]+)@)?(?P<host>[^:]+):(?P<path>.*)", value
    )
    if match is None:
        return None
    return match.group("user"), match.group("host"), match.group("path")


def _sshfs_port(options: tuple[str, ...]) -> int:
    for option in options:
        key, separator, value = option.partition("=")
        if separator and key in {"port", "sshfs_port"}:
            try:
                port = int(value)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                return port
    return 22


def _collect_sshfs_mounts(mounts: list[_MountInfo]):
    values: list[SshfsMount] = []
    warnings: list[CollectorMessage] = []
    for mount in mounts:
        if mount.filesystem_type != "fuse.sshfs":
            continue
        parsed = _sshfs_source(mount.source)
        if parsed is None:
            warnings.append(
                CollectorMessage(
                    source="mounts",
                    message=f"cannot parse SSHFS source for {mount.mount_point}",
                )
            )
            continue
        username, target_host, remote_path = parsed
        values.append(
            SshfsMount(
                local_path=mount.mount_point,
                target_host=target_host,
                target_port=_sshfs_port(mount.super_options),
                username=username,
                remote_path=remote_path,
            )
        )
    return sorted(values, key=lambda item: item.local_path), warnings


def _windows_path(source: str, root: str, super_options: tuple[str, ...]) -> str | None:
    drive = source if _WINDOWS_ROOT.fullmatch(source) else None
    if drive is None:
        joined_options = ";".join(super_options)
        match = re.search(r"(?:^|;)path=([^;]+)", joined_options)
        if match and _WINDOWS_ROOT.fullmatch(match.group(1)):
            drive = match.group(1)
    if drive is None:
        return None
    drive = drive.rstrip("\\/") + "\\"
    relative = root.strip("/")
    if not relative:
        return drive
    return drive + relative.replace("/", "\\")


def _paths_overlap(first: str, second: str) -> bool:
    first_path = PurePosixPath(first)
    second_path = PurePosixPath(second)
    return (
        first_path == second_path
        or first_path.is_relative_to(second_path)
        or second_path.is_relative_to(first_path)
    )


def _collect_windows_mappings(
    mounts: list[_MountInfo], sftp_exports: list[SftpExport]
):
    mappings: dict[str, WindowsPathMapping] = {}
    exported_roots = [export.chroot_directory for export in sftp_exports]
    for mount in mounts:
        if mount.filesystem_type != "9p":
            continue
        if not any(_paths_overlap(mount.mount_point, root) for root in exported_roots):
            continue
        option_text = ";".join(mount.super_options)
        if "aname=drvfs" not in option_text:
            continue
        windows_path = _windows_path(mount.source, mount.root, mount.super_options)
        if windows_path:
            mappings[mount.mount_point] = WindowsPathMapping(
                linux_path=mount.mount_point,
                windows_path=windows_path,
            )
    return sorted(mappings.values(), key=lambda item: item.linux_path)


class _SshConfigReader:
    def __init__(self, host_root: Path):
        self.host_root = host_root
        self.ssh_root = PurePosixPath("/etc/ssh")
        self.warnings: list[CollectorMessage] = []

    def read(self) -> list[list[str]]:
        return self._read_file(PurePosixPath("/etc/ssh/sshd_config"), set())

    def _safe_virtual_path(self, value: PurePosixPath) -> PurePosixPath:
        parts: list[str] = []
        for part in value.parts:
            if part in {"", "/", "."}:
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        result = PurePosixPath("/").joinpath(*parts)
        if not result.is_relative_to(self.ssh_root):
            raise _ExternalSshPath
        return result

    def _actual_path(self, virtual_path: PurePosixPath) -> Path:
        safe = self._safe_virtual_path(virtual_path)
        return self.host_root.joinpath(*safe.parts[1:])

    def _follow_symlink(self, virtual_path: PurePosixPath) -> PurePosixPath:
        current = self._safe_virtual_path(virtual_path)
        for _ in range(20):
            actual = self._actual_path(current)
            if not actual.is_symlink():
                return current
            target = PurePosixPath(actual.readlink().as_posix())
            current = self._safe_virtual_path(
                target if target.is_absolute() else current.parent / target
            )
        raise ValueError("too many SSH configuration symlink levels")

    def _include_matches(self, pattern: str) -> list[PurePosixPath]:
        virtual_pattern = PurePosixPath(pattern)
        if not virtual_pattern.is_absolute():
            virtual_pattern = self.ssh_root / virtual_pattern
        try:
            actual_pattern = self._actual_path(virtual_pattern)
        except _ExternalSshPath:
            return []
        values = []
        for actual in sorted(glob.glob(str(actual_pattern))):
            try:
                relative = Path(actual).relative_to(self.host_root)
            except ValueError:
                continue
            values.append(PurePosixPath("/") / PurePosixPath(relative.as_posix()))
        return values

    def _read_file(
        self, virtual_path: PurePosixPath, stack: set[PurePosixPath]
    ) -> list[list[str]]:
        try:
            resolved = self._follow_symlink(virtual_path)
            if resolved in stack:
                raise ValueError("recursive SSH configuration include")
            text = self._actual_path(resolved).read_text(encoding="utf-8")
        except _ExternalSshPath:
            return []
        except Exception as exc:
            self.warnings.append(
                CollectorMessage(
                    source="mounts",
                    message=f"cannot read SSH configuration {virtual_path.name}: {exc}",
                )
            )
            return []

        lines: list[list[str]] = []
        next_stack = {*stack, resolved}
        for line_number, line in enumerate(text.splitlines(), start=1):
            try:
                tokens = shlex.split(line, comments=True, posix=True)
            except ValueError as exc:
                self.warnings.append(
                    CollectorMessage(
                        source="mounts",
                        message=(
                            f"cannot parse SSH configuration {virtual_path.name}:"
                            f"{line_number}: {exc}"
                        ),
                    )
                )
                continue
            if not tokens:
                continue
            if tokens[0].lower() == "include":
                for pattern in tokens[1:]:
                    for included in self._include_matches(pattern):
                        lines.extend(self._read_file(included, next_stack))
                continue
            lines.append(tokens)
        return lines


def _host_user_homes(host_root: Path) -> dict[str, str]:
    try:
        text = (host_root / "etc/passwd").read_text(encoding="utf-8")
    except OSError:
        return {}
    homes = {}
    for line in text.splitlines():
        columns = line.split(":")
        if len(columns) >= 6:
            homes[columns[0]] = columns[5]
    return homes


def _exact_match_users(arguments: list[str]) -> list[str]:
    if len(arguments) != 2 or arguments[0].lower() != "user":
        return []
    users = arguments[1].split(",")
    if any(not user or any(char in user for char in "*!?") for user in users):
        return []
    return users


def _expand_chroot(value: str, username: str, home: str | None) -> str | None:
    if value.lower() == "none":
        return None
    if "%h" in value and not home:
        return None
    marker = "\0PERCENT\0"
    expanded = value.replace("%%", marker).replace("%u", username)
    expanded = expanded.replace("%h", home or "").replace(marker, "%")
    if not expanded.startswith("/"):
        return None
    return str(PurePosixPath(expanded))


def _collect_sftp_exports(host_root: Path):
    config_path = host_root / "etc/ssh/sshd_config"
    if not config_path.exists():
        return [], []
    reader = _SshConfigReader(host_root)
    lines = reader.read()
    ports: list[int] = []
    matches: dict[str, dict[str, str]] = {}
    current_users: list[str] = []
    for tokens in lines:
        keyword = tokens[0].lower()
        arguments = tokens[1:]
        if keyword == "match":
            current_users = _exact_match_users(arguments)
            continue
        if not current_users:
            if keyword == "port" and arguments:
                try:
                    port = int(arguments[0])
                except ValueError:
                    continue
                if 1 <= port <= 65535 and port not in ports:
                    ports.append(port)
            continue
        if keyword not in {"chrootdirectory", "forcecommand"} or not arguments:
            continue
        for username in current_users:
            matches.setdefault(username, {}).setdefault(keyword, " ".join(arguments))

    if not ports:
        ports = [22]
    homes = _host_user_homes(host_root)
    exports: list[SftpExport] = []
    for username, values in matches.items():
        force_command = values.get("forcecommand", "")
        if not force_command.lower().startswith("internal-sftp"):
            continue
        chroot = _expand_chroot(values.get("chrootdirectory", "none"), username, homes.get(username))
        if chroot is None:
            continue
        exports.append(
            SftpExport(username=username, ports=ports, chroot_directory=chroot)
        )
    return sorted(exports, key=lambda item: item.username), reader.warnings


def collect_mount_topology(host_root: str):
    root = Path(host_root)
    try:
        mountinfo_text = (root / "proc/1/mountinfo").read_text(encoding="utf-8")
    except OSError as exc:
        return [], [], [], [
            CollectorMessage(source="mounts", message=f"cannot read host mount table: {exc}")
        ]

    mounts, warnings = _parse_mountinfo(mountinfo_text)
    sshfs_mounts, sshfs_warnings = _collect_sshfs_mounts(mounts)
    sftp_exports, sftp_warnings = _collect_sftp_exports(root)
    windows_mappings = _collect_windows_mappings(mounts, sftp_exports)
    return (
        sshfs_mounts,
        sftp_exports,
        windows_mappings,
        [*warnings, *sshfs_warnings, *sftp_warnings],
    )
