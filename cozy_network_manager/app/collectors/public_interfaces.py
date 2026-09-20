from __future__ import annotations

import glob
import json
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path, PurePosixPath

from cozy_network_manager.app.schemas import CollectorMessage, PublicInterface


_WILDCARD_ADDRESSES = {"0.0.0.0", "::", "*"}


class _ExternalNginxPath(ValueError):
    pass


@dataclass
class _Directive:
    name: str
    arguments: list[str]
    children: list[_Directive] | None = None


@dataclass(frozen=True)
class _Listener:
    address: str
    port: int
    ssl: bool = False


def _tokenize_nginx(text: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                current.append(char)
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            else:
                current.append(char)
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "#":
            if current:
                tokens.append("".join(current))
                current = []
            newline = text.find("\n", index)
            if newline == -1:
                break
            index = newline
        elif char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
        elif char in {"{", "}", ";"}:
            if current:
                tokens.append("".join(current))
                current = []
            tokens.append(char)
        else:
            current.append(char)
        index += 1
    if quote:
        raise ValueError("unterminated quoted string")
    if current:
        tokens.append("".join(current))
    return tokens


def _parse_directives(tokens: list[str], index: int = 0, nested: bool = False):
    directives: list[_Directive] = []
    while index < len(tokens):
        if tokens[index] == "}":
            if not nested:
                raise ValueError("unexpected closing brace")
            return directives, index + 1
        words: list[str] = []
        while index < len(tokens) and tokens[index] not in {"{", "}", ";"}:
            words.append(tokens[index])
            index += 1
        if not words:
            if index < len(tokens) and tokens[index] == ";":
                index += 1
                continue
            raise ValueError("directive name is missing")
        if index >= len(tokens):
            raise ValueError(f"directive {words[0]!r} is missing a terminator")
        terminator = tokens[index]
        if terminator == "}":
            raise ValueError(f"directive {words[0]!r} is missing a terminator")
        if terminator == ";":
            directives.append(_Directive(words[0], words[1:]))
            index += 1
            continue
        children, index = _parse_directives(tokens, index + 1, nested=True)
        directives.append(_Directive(words[0], words[1:], children))
    if nested:
        raise ValueError("unterminated block")
    return directives, index


class _NginxConfigReader:
    def __init__(self, host_root: Path):
        self.host_root = host_root
        self.nginx_root = PurePosixPath("/etc/nginx")
        self.warnings: list[CollectorMessage] = []

    def read(self) -> list[_Directive]:
        return self._read_file(PurePosixPath("/etc/nginx/nginx.conf"), set())

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
        if not result.is_relative_to(self.nginx_root):
            raise _ExternalNginxPath
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
        raise ValueError("too many nginx symlink levels")

    def _include_matches(self, pattern: str) -> list[PurePosixPath]:
        virtual_pattern = PurePosixPath(pattern)
        if not virtual_pattern.is_absolute():
            virtual_pattern = self.nginx_root / virtual_pattern
        try:
            actual_pattern = self._actual_path(virtual_pattern)
        except _ExternalNginxPath:
            return []
        matches = []
        for actual in sorted(glob.glob(str(actual_pattern))):
            try:
                relative = Path(actual).relative_to(self.host_root)
            except ValueError:
                continue
            matches.append(PurePosixPath("/") / PurePosixPath(relative.as_posix()))
        return matches

    def _read_file(
        self, virtual_path: PurePosixPath, stack: set[PurePosixPath]
    ) -> list[_Directive]:
        try:
            resolved = self._follow_symlink(virtual_path)
            if resolved in stack:
                raise ValueError("recursive nginx include")
            text = self._actual_path(resolved).read_text(encoding="utf-8")
            directives, _ = _parse_directives(_tokenize_nginx(text))
        except _ExternalNginxPath:
            return []
        except Exception as exc:
            self.warnings.append(
                CollectorMessage(
                    source="public-interfaces",
                    message=f"cannot read nginx configuration {virtual_path.name}: {exc}",
                )
            )
            return []

        expanded: list[_Directive] = []
        next_stack = {*stack, resolved}
        for directive in directives:
            if directive.name == "include":
                for pattern in directive.arguments:
                    for included in self._include_matches(pattern):
                        expanded.extend(self._read_file(included, next_stack))
                continue
            if directive.children is not None:
                directive.children = self._expand_children(directive.children, next_stack)
            expanded.append(directive)
        return expanded

    def _expand_children(
        self, directives: list[_Directive], stack: set[PurePosixPath]
    ) -> list[_Directive]:
        expanded: list[_Directive] = []
        for directive in directives:
            if directive.name == "include":
                for pattern in directive.arguments:
                    for included in self._include_matches(pattern):
                        expanded.extend(self._read_file(included, stack))
                continue
            if directive.children is not None:
                directive.children = self._expand_children(directive.children, stack)
            expanded.append(directive)
        return expanded


def _walk_blocks(directives: list[_Directive], name: str):
    for directive in directives:
        if directive.name == name and directive.children is not None:
            yield directive
        if directive.children is not None:
            yield from _walk_blocks(directive.children, name)


def _parse_listen(arguments: list[str]) -> _Listener | None:
    if not arguments:
        return None
    value = arguments[0]
    if value.startswith("unix:"):
        return None
    ssl = "ssl" in arguments[1:]
    address = "0.0.0.0"
    port_text = value
    if value.startswith("[") and "]:" in value:
        address, port_text = value[1:].split("]:", 1)
    elif value.count(":") == 1:
        address, port_text = value.rsplit(":", 1)
    elif ":" in value:
        return None
    elif not value.isdigit():
        address = value
        port_text = "80"
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return _Listener(address=address, port=port, ssl=ssl or port == 443)


def _nginx_hostname(value: str) -> str | None:
    hostname = value.rstrip(".").lower()
    if len(hostname) > 253 or "." not in hostname or not hostname.isascii():
        return None
    labels = hostname.split(".")
    if any(
        not 1 <= len(label) <= 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        return None
    try:
        ip_address(hostname)
    except ValueError:
        return hostname
    return None


def _is_public_bind(address: str) -> bool:
    try:
        return ip_address(address).is_global
    except ValueError:
        return False


def _nginx_listeners(host_root: Path, node_ip: str):
    reader = _NginxConfigReader(host_root)
    config_path = host_root / "etc/nginx/nginx.conf"
    if not config_path.exists():
        return [], [], []
    directives = reader.read()
    vpn_listeners: set[_Listener] = set()
    public_sites: set[tuple[_Listener, str]] = set()
    for server in _walk_blocks(directives, "server"):
        listen_directives = [item for item in server.children or [] if item.name == "listen"]
        parsed = [_parse_listen(item.arguments) for item in listen_directives]
        if not listen_directives:
            parsed = [_Listener(address="0.0.0.0", port=80)]
        hostnames = {
            hostname
            for item in server.children or []
            if item.name == "server_name"
            for value in item.arguments
            if (hostname := _nginx_hostname(value)) is not None
        }
        for listener in parsed:
            if listener and listener.address in {*_WILDCARD_ADDRESSES, node_ip}:
                vpn_listeners.add(listener)
            if listener and (
                listener.address in _WILDCARD_ADDRESSES
                or _is_public_bind(listener.address)
            ):
                public_sites.update((listener, hostname) for hostname in hostnames)
    return (
        sorted(vpn_listeners, key=lambda item: (item.port, item.ssl, item.address)),
        sorted(public_sites, key=lambda item: (item[0].port, item[0].address, item[1])),
        reader.warnings,
    )


def _decode_proc_address(value: str, ipv6: bool):
    raw = bytes.fromhex(value)
    if not ipv6:
        return str(IPv4Address(raw[::-1]))
    reordered = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
    return str(IPv6Address(reordered))


def _host_tcp_listeners(proc_root: Path) -> set[tuple[str, int]]:
    listeners: set[tuple[str, int]] = set()
    for filename, ipv6 in (("tcp", False), ("tcp6", True)):
        try:
            lines = (proc_root / "1/net" / filename).read_text(encoding="utf-8").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            columns = line.split()
            if len(columns) < 4 or columns[3] != "0A":
                continue
            try:
                address_hex, port_hex = columns[1].split(":", 1)
                listeners.add((_decode_proc_address(address_hex, ipv6), int(port_hex, 16)))
            except (ValueError, IndexError):
                continue
    return listeners


def _host_processes(proc_root: Path) -> set[str]:
    processes: set[str] = set()
    for path in proc_root.glob("[0-9]*/comm"):
        try:
            processes.add(path.read_text(encoding="utf-8").strip())
        except OSError:
            continue
    return processes


def _port_is_open(listeners: set[tuple[str, int]], node_ip: str, port: int) -> bool:
    return any(
        listener_port == port and address in {node_ip, "0.0.0.0", "::"}
        for address, listener_port in listeners
    )


def _interface_url(host: str, port: int, ssl: bool = False, path: str = "/") -> str:
    scheme = "https" if ssl else "http"
    default_port = 443 if ssl else 80
    authority = host if port == default_port else f"{host}:{port}"
    normalized_path = "/" + path.strip("/")
    if normalized_path != "/":
        normalized_path += "/"
    return f"{scheme}://{authority}{normalized_path}"


def _transmission_web_path(rpc_path: str) -> str:
    return f"/{rpc_path.strip('/')}/web/"


def _collect_nginx(
    host_root: Path,
    node_ip: str,
    processes: set[str],
    tcp_listeners: set[tuple[str, int]],
):
    configured, public_sites, warnings = _nginx_listeners(host_root, node_ip)
    running = "nginx" in processes
    by_url: dict[str, PublicInterface] = {}
    for listener in configured:
        url = _interface_url(node_ip, listener.port, listener.ssl)
        up = running and _port_is_open(tcp_listeners, node_ip, listener.port)
        existing = by_url.get(url)
        status = "up" if up or (existing and existing.status == "up") else "down"
        by_url[url] = PublicInterface(service="nginx", url=url, status=status)
    for listener, hostname in public_sites:
        url = _interface_url(hostname, listener.port, listener.ssl)
        up = running and _port_is_open(tcp_listeners, listener.address, listener.port)
        existing = by_url.get(url)
        status = "up" if up or (existing and existing.status == "up") else "down"
        by_url[url] = PublicInterface(service="nginx", url=url, status=status)
    return list(by_url.values()), warnings


def _transmission_settings(host_root: Path):
    candidates = (
        host_root / "etc/transmission-daemon/settings.json",
        host_root / "etc/transmission/settings.json",
    )
    path = next((candidate for candidate in candidates if candidate.exists()), None)
    if path is None:
        return None, []
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(settings, dict):
            raise ValueError("settings must contain a JSON object")
    except Exception as exc:
        return None, [
            CollectorMessage(
                source="public-interfaces",
                message=f"cannot read Transmission settings: {exc}",
            )
        ]
    return settings, []


def _collect_transmission(
    host_root: Path,
    node_ip: str,
    processes: set[str],
    tcp_listeners: set[tuple[str, int]],
):
    settings, warnings = _transmission_settings(host_root)
    if settings is None or not settings.get("rpc-enabled", True):
        return [], warnings
    bind_address = str(settings.get("rpc-bind-address", "0.0.0.0"))
    if bind_address not in {*_WILDCARD_ADDRESSES, node_ip}:
        return [], warnings
    try:
        port = int(settings.get("rpc-port", 9091))
        if not 1 <= port <= 65535:
            raise ValueError("outside the TCP port range")
    except (TypeError, ValueError) as exc:
        warnings.append(
            CollectorMessage(
                source="public-interfaces",
                message=f"invalid Transmission RPC port: {exc}",
            )
        )
        return [], warnings
    path = _transmission_web_path(str(settings.get("rpc-url", "/transmission/")))
    ssl = bool(settings.get("rpc-ssl-enabled", False))
    running = any(name.startswith("transmission-da") for name in processes)
    status = "up" if running and _port_is_open(tcp_listeners, node_ip, port) else "down"
    return [
        PublicInterface(
            service="transmission",
            url=_interface_url(node_ip, port, ssl, path),
            status=status,
        )
    ], warnings


def collect_public_interfaces(
    host_root: str, node_ip: str | None
) -> tuple[list[PublicInterface], list[CollectorMessage]]:
    if not node_ip:
        return [], []
    try:
        node_ip = str(ip_address(node_ip))
    except ValueError:
        return [], [
            CollectorMessage(
                source="public-interfaces",
                message="cannot collect VPN interfaces without a valid node IP",
            )
        ]
    if ":" in node_ip:
        return [], [
            CollectorMessage(
                source="public-interfaces",
                message="IPv6 node identities are not supported for public interface reporting",
            )
        ]

    root = Path(host_root)
    processes = _host_processes(root / "proc")
    tcp_listeners = _host_tcp_listeners(root / "proc")
    nginx, nginx_warnings = _collect_nginx(root, node_ip, processes, tcp_listeners)
    transmission, transmission_warnings = _collect_transmission(
        root, node_ip, processes, tcp_listeners
    )
    interfaces = sorted([*nginx, *transmission], key=lambda item: (item.service, item.url))
    return interfaces, [*nginx_warnings, *transmission_warnings]
