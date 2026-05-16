from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import AnyHttpUrl, BaseModel, Field, field_validator


Mode = Literal["head", "minion"]


class KnownNode(BaseModel):
    name: str
    expected_vpn_ip: str
    minion_api_url: AnyHttpUrl | None = None
    tags: list[str] = Field(default_factory=list)
    notes: str = ""
    os_override: str | None = None


class DnsConfig(BaseModel):
    domains: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)


class AppConfig(BaseModel):
    mode: Mode = "head"
    node_name: str = "cozy-head"
    listen_host: str = "0.0.0.0"
    listen_port: int = 8000
    database_url: str = "postgresql+psycopg://cozy:cozy@postgres:5432/cozy_network_manager"
    polling_interval_seconds: int = 60
    stale_after_seconds: int = 300
    wireguard_interfaces: list[str] = Field(default_factory=list)
    device_subnets: list[str] = Field(default_factory=lambda: ["10.46.0.0/24"])
    known_nodes: list[KnownNode] = Field(default_factory=list)
    dns: DnsConfig = Field(default_factory=DnsConfig)
    host_root: str = "/host"

    @field_validator("polling_interval_seconds", "stale_after_seconds")
    @classmethod
    def positive_int(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("must be greater than zero")
        return value


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
        "listen_host": os.getenv("CNM_LISTEN_HOST", config.listen_host),
        "listen_port": _env_int("CNM_LISTEN_PORT", config.listen_port),
        "database_url": os.getenv("CNM_DATABASE_URL", config.database_url),
        "polling_interval_seconds": _env_int(
            "CNM_POLLING_INTERVAL_SECONDS", config.polling_interval_seconds
        ),
        "stale_after_seconds": _env_int("CNM_STALE_AFTER_SECONDS", config.stale_after_seconds),
        "host_root": os.getenv("CNM_HOST_ROOT", config.host_root),
    }
    return config.model_copy(update=overrides)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    return load_config()


def clear_config_cache() -> None:
    get_config.cache_clear()
