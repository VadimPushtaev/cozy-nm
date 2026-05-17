from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator


Mode = Literal["head", "minion"]


class KnownNode(BaseModel):
    name: str
    expected_vpn_ip: str
    tags: list[str] = Field(default_factory=list)
    notes: str = ""
    os_override: str | None = None


class DnsConfig(BaseModel):
    domains: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)


class DeploymentConfig(BaseModel):
    head: str | None = None
    minions: list[str] = Field(default_factory=list)

    def ips(self) -> list[str]:
        values = []
        if self.head:
            values.append(self.head)
        values.extend(self.minions)
        return sorted(set(values))


class AppConfig(BaseModel):
    mode: Mode = "head"
    node_name: str = "cozy-head"
    node_ip: str | None = None
    listen_host: str = "0.0.0.0"
    listen_port: int = 8000
    database_url: str = "postgresql+psycopg://cozy:cozy@postgres:5432/cozy_network_manager"
    polling_interval_seconds: int = 60
    device_scan_interval_seconds: int = 10
    stale_after_seconds: int = 300
    wireguard_interfaces: list[str] = Field(default_factory=list)
    device_subnets: list[str] = Field(default_factory=lambda: ["10.46.0.0/24"])
    wireguard_clients_path: str = "/host/wireguard/clients"
    minion_port: int = 8000
    public_ipv4_url: str = "https://ifconfig.me/ip"
    known_nodes: list[KnownNode] = Field(default_factory=list)
    minions: list[str] = Field(default_factory=list)
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    dns: DnsConfig = Field(default_factory=DnsConfig)
    host_root: str = "/host"

    @field_validator("polling_interval_seconds", "device_scan_interval_seconds", "stale_after_seconds")
    @classmethod
    def positive_int(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("must be greater than zero")
        return value

    def dns_hostnames(self) -> list[str]:
        return sorted(
            {
                hostname.strip().rstrip(".")
                for hostname in self.dns.hostnames
                if hostname.strip().rstrip(".")
            }
        )

    def dns_domains(self) -> list[str]:
        return sorted(
            {
                domain.strip().rstrip(".")
                for domain in self.dns.domains
                if domain.strip().rstrip(".")
            }
        )

    def node_identifier(self) -> str:
        if self.node_ip:
            return self.node_ip
        if self.mode == "head" and self.deployment.head:
            return self.deployment.head
        return self.node_name

    def topology_nodes(self) -> list[KnownNode]:
        if self.known_nodes:
            return self.known_nodes
        return [
            KnownNode(name=ip, expected_vpn_ip=ip)
            for ip in self.deployment.ips()
        ]

    def minion_targets(self, include_self: bool = False) -> list[tuple[str, str]]:
        if self.deployment.minions:
            current = self.node_ip or (self.deployment.head if self.mode == "head" else None)
            targets = []
            for ip in self.deployment.minions:
                if not include_self and current and ip == current:
                    continue
                targets.append((ip, f"http://{ip}:{self.minion_port}"))
            return targets

        nodes_by_name = {node.name: node for node in self.topology_nodes()}
        targets: list[tuple[str, str]] = []
        for name in self.minions:
            if not include_self and name == self.node_identifier():
                continue
            node = nodes_by_name.get(name)
            if node is None:
                continue
            targets.append((name, f"http://{node.expected_vpn_ip}:{self.minion_port}"))
        return targets


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file {path} must contain a mapping")
    return data


def _env_int(name: str, current: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return current
    return int(raw)


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path or os.getenv("CNM_CONFIG", "config.example.yml"))
    data = _read_yaml(config_path)
    config = AppConfig.model_validate(data)

    overrides: dict[str, Any] = {
        "mode": os.getenv("CNM_MODE", config.mode),
        "node_name": os.getenv("CNM_NODE_NAME", config.node_name),
        "node_ip": os.getenv("CNM_NODE_IP", config.node_ip or "") or None,
        "listen_host": os.getenv("CNM_LISTEN_HOST", config.listen_host),
        "listen_port": _env_int("CNM_LISTEN_PORT", config.listen_port),
        "database_url": os.getenv("CNM_DATABASE_URL", config.database_url),
        "polling_interval_seconds": _env_int(
            "CNM_POLLING_INTERVAL_SECONDS", config.polling_interval_seconds
        ),
        "device_scan_interval_seconds": _env_int(
            "CNM_DEVICE_SCAN_INTERVAL_SECONDS", config.device_scan_interval_seconds
        ),
        "stale_after_seconds": _env_int("CNM_STALE_AFTER_SECONDS", config.stale_after_seconds),
        "host_root": os.getenv("CNM_HOST_ROOT", config.host_root),
        "wireguard_clients_path": os.getenv(
            "CNM_WIREGUARD_CLIENTS_PATH", config.wireguard_clients_path
        ),
        "minion_port": _env_int("CNM_MINION_PORT", config.minion_port),
        "public_ipv4_url": os.getenv("CNM_PUBLIC_IPV4_URL", config.public_ipv4_url),
    }
    return config.model_copy(update=overrides)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    return load_config()


def clear_config_cache() -> None:
    get_config.cache_clear()
