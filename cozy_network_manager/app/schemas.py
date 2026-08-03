from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CollectorMessage(BaseModel):
    source: str
    message: str


class HostInfo(BaseModel):
    hostname: str | None = None
    public_ipv4: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    kernel_version: str | None = None
    architecture: str | None = None
    uptime_seconds: float | None = None
    interfaces: list[dict[str, Any]] = Field(default_factory=list)


class WireGuardPeer(BaseModel):
    public_key: str
    allowed_ips: list[str] = Field(default_factory=list)
    latest_handshake: int | None = None
    transfer_rx: int | None = None
    transfer_tx: int | None = None
    endpoint: str | None = None


class WireGuardInterface(BaseModel):
    name: str
    public_key: str | None = None
    listen_port: int | None = None
    local_ips: list[str] = Field(default_factory=list)
    peers: list[WireGuardPeer] = Field(default_factory=list)


class DockerContainer(BaseModel):
    id: str
    name: str
    image: str | None = None
    status: str | None = None
    command: str | list[str] | None = None
    published_ports: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, str] = Field(default_factory=dict)


class SocatForward(BaseModel):
    container_name: str
    image: str | None = None
    status: str | None = None
    command: str | list[str] | None = None
    published_ports: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, str] = Field(default_factory=dict)
    source_port: int | None = None
    destination_host: str | None = None
    destination_port: int | None = None


class BridgeDefinitionInput(BaseModel):
    name: str
    listen_port: int
    target_host: str
    target_port: int


class BridgeDefinition(BaseModel):
    name: str
    listen_port: int | None = None
    target_host: str | None = None
    target_port: int | None = None
    managed: bool = True
    validation_error: str | None = None
    runtime_state: str | None = None
    runtime_status: str | None = None
    container_name: str | None = None


class BridgeOrphan(BaseModel):
    name: str
    service: str
    state: str | None = None
    status: str | None = None


class BridgeProject(BaseModel):
    node_ip: str
    compose_dir: str
    compose_file: str
    compose_valid: bool = True
    pending_apply: bool = False
    services: list[BridgeDefinition] = Field(default_factory=list)
    orphans: list[BridgeOrphan] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class BridgeOperationResult(BaseModel):
    ok: bool = True
    message: str
    stdout: str = ""
    stderr: str = ""
    project: BridgeProject | None = None


class Snapshot(BaseModel):
    node_name: str
    timestamp: datetime = Field(default_factory=utc_now)
    host: HostInfo = Field(default_factory=HostInfo)
    wireguard: list[WireGuardInterface] = Field(default_factory=list)
    docker_containers: list[DockerContainer] = Field(default_factory=list)
    socat_forwards: list[SocatForward] = Field(default_factory=list)
    warnings: list[CollectorMessage] = Field(default_factory=list)
    errors: list[CollectorMessage] = Field(default_factory=list)
