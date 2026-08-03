from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
import fcntl
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Iterator

import docker
import yaml

from cozy_network_manager.app.config import AppConfig, BridgeHostConfig
from cozy_network_manager.app.schemas import (
    BridgeDefinition,
    BridgeDefinitionInput,
    BridgeOperationResult,
    BridgeOrphan,
    BridgeProject,
)


SERVICE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}")
DNS_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
MANAGED_SERVICE_KEYS = {
    "build",
    "image",
    "container_name",
    "restart",
    "ports",
    "environment",
}
BRIDGE_ENV_KEYS = {"LISTEN_PORT", "TARGET_HOST", "TARGET_PORT"}
MAX_COMMAND_OUTPUT = 4_000


class BridgeManagerError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


class BridgeCommandError(BridgeManagerError):
    def __init__(self, message: str, stdout: str = "", stderr: str = ""):
        super().__init__(message, status_code=409)
        self.stdout = stdout
        self.stderr = stderr


def _limited(value: str) -> str:
    return value[-MAX_COMMAND_OUTPUT:]


def _environment_dict(raw: object) -> dict[str, str]:
    if isinstance(raw, dict):
        return {str(key): str(value) for key, value in raw.items() if value is not None}
    if isinstance(raw, list):
        result: dict[str, str] = {}
        for item in raw:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                result[key] = value
        return result
    return {}


def _integer(value: object) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if 1 <= parsed <= 65_535 else None


def validate_bridge_input(value: BridgeDefinitionInput) -> None:
    if SERVICE_NAME_RE.fullmatch(value.name) is None:
        raise BridgeManagerError(
            "Bridge name must start with a letter or digit and contain only letters, digits, dot, underscore, or dash."
        )
    if not 1 <= value.listen_port <= 65_535 or not 1 <= value.target_port <= 65_535:
        raise BridgeManagerError("Ports must be between 1 and 65535.")
    try:
        parsed_ip = ip_address(value.target_host)
    except ValueError:
        parsed_ip = None
    if parsed_ip is not None and parsed_ip.version != 4:
        raise BridgeManagerError("Only IPv4 addresses and DNS hostnames are supported.")
    if parsed_ip is None and DNS_NAME_RE.fullmatch(value.target_host) is None:
        raise BridgeManagerError("Target host must be an IPv4 address or a safe DNS hostname.")


def _standard_service(value: BridgeDefinitionInput) -> dict:
    port = str(value.listen_port)
    return {
        "build": ".",
        "image": "socat-bridge:latest",
        "container_name": value.name,
        "restart": "unless-stopped",
        "ports": [f"{port}:{port}"],
        "environment": {
            "LISTEN_PORT": port,
            "TARGET_HOST": value.target_host,
            "TARGET_PORT": str(value.target_port),
        },
    }


def _parse_service(name: str, raw: object) -> BridgeDefinition:
    if not isinstance(raw, dict):
        return BridgeDefinition(
            name=name,
            managed=False,
            validation_error="service definition must be a mapping",
        )

    environment = _environment_dict(raw.get("environment"))
    listen_port = _integer(environment.get("LISTEN_PORT"))
    target_host = environment.get("TARGET_HOST")
    target_port = _integer(environment.get("TARGET_PORT"))
    errors: list[str] = []
    unknown_keys = sorted(set(raw) - MANAGED_SERVICE_KEYS)
    if unknown_keys:
        errors.append(f"unsupported keys: {', '.join(unknown_keys)}")
    if raw.get("image") != "socat-bridge:latest":
        errors.append("image must be socat-bridge:latest")
    if raw.get("build") != ".":
        errors.append("build must be '.'")
    if raw.get("container_name") != name:
        errors.append("container_name must match the service name")
    if raw.get("restart") != "unless-stopped":
        errors.append("restart must be unless-stopped")
    if set(environment) != BRIDGE_ENV_KEYS:
        errors.append("environment must contain LISTEN_PORT, TARGET_HOST, and TARGET_PORT")
    if listen_port is None or target_port is None or not target_host:
        errors.append("bridge ports and target host must be valid")
    if listen_port is not None:
        ports = raw.get("ports")
        expected_port = f"{listen_port}:{listen_port}"
        if not isinstance(ports, list) or expected_port not in [str(item) for item in ports]:
            errors.append(f"ports must publish {expected_port}")

    if not errors and listen_port is not None and target_port is not None and target_host:
        try:
            validate_bridge_input(
                BridgeDefinitionInput(
                    name=name,
                    listen_port=listen_port,
                    target_host=target_host,
                    target_port=target_port,
                )
            )
        except BridgeManagerError as exc:
            errors.append(str(exc))

    return BridgeDefinition(
        name=name,
        listen_port=listen_port,
        target_host=target_host,
        target_port=target_port,
        managed=not errors,
        validation_error="; ".join(errors) if errors else None,
        container_name=str(raw.get("container_name") or name),
    )


class BridgeManager:
    def __init__(self, config: AppConfig):
        if config.mode != "minion":
            raise BridgeManagerError("Bridge management is available only in minion mode.", 404)
        host = config.bridge_host()
        if host is None:
            raise BridgeManagerError("This minion is not whitelisted for bridge management.", 403)
        self.config = config
        self.host: BridgeHostConfig = host
        self.compose_dir = Path(host.compose_dir)
        self.compose_file = self.compose_dir / host.compose_file
        self.metadata_dir = self.compose_dir / ".cozy-nm"
        self.applied_hash_file = self.metadata_dir / "applied.sha256"
        self.lock_file = self.metadata_dir / "lock"
        self.backups_dir = self.metadata_dir / "backups"

    def _ensure_paths(self) -> None:
        if not self.compose_dir.exists() or not self.compose_dir.is_dir():
            raise BridgeManagerError(f"Compose directory does not exist: {self.compose_dir}", 503)
        self.metadata_dir.mkdir(mode=0o700, exist_ok=True)
        self.backups_dir.mkdir(mode=0o700, exist_ok=True)
        dockerignore = self.compose_dir / ".dockerignore"
        try:
            contents = dockerignore.read_text(encoding="utf-8") if dockerignore.exists() else ""
            if ".cozy-nm/" not in {line.strip() for line in contents.splitlines()}:
                separator = "" if not contents or contents.endswith("\n") else "\n"
                dockerignore.write_text(f"{contents}{separator}.cozy-nm/\n", encoding="utf-8")
        except OSError as exc:
            raise BridgeManagerError(f"Cannot update {dockerignore}: {exc}", 503) from exc

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._ensure_paths()
        descriptor = os.open(self.lock_file, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _load_document(self) -> dict:
        if not self.compose_file.exists():
            return {"services": {}}
        try:
            document = yaml.safe_load(self.compose_file.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise BridgeManagerError(f"Cannot read Compose file: {exc}", 503) from exc
        if not isinstance(document, dict):
            raise BridgeManagerError("Compose file must contain a mapping.")
        services = document.setdefault("services", {})
        if not isinstance(services, dict):
            raise BridgeManagerError("Compose services must contain a mapping.")
        return document

    def _validate_document(self, document: dict) -> None:
        services = document.get("services")
        if not isinstance(services, dict):
            raise BridgeManagerError("Compose services must contain a mapping.")
        used_ports: dict[int, str] = {}
        for name, raw in services.items():
            bridge = _parse_service(str(name), raw)
            if bridge.managed and bridge.listen_port is not None:
                owner = used_ports.get(bridge.listen_port)
                if owner:
                    raise BridgeManagerError(
                        f"Listen port {bridge.listen_port} is already used by {owner}."
                    )
                used_ports[bridge.listen_port] = bridge.name

    def _run_compose(
        self,
        arguments: list[str],
        *,
        compose_file: Path | None = None,
        timeout: int = 30,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "docker",
            "compose",
            "--project-directory",
            str(self.compose_dir),
            "-f",
            str(compose_file or self.compose_file),
            *arguments,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise BridgeManagerError("Docker Compose CLI is unavailable on this minion.", 503) from exc
        except subprocess.TimeoutExpired as exc:
            raise BridgeCommandError(f"Docker Compose timed out after {timeout} seconds.") from exc
        result.stdout = _limited(result.stdout)
        result.stderr = _limited(result.stderr)
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
            raise BridgeCommandError(f"Docker Compose failed: {detail}", result.stdout, result.stderr)
        return result

    def _compose_is_valid(self, compose_file: Path | None = None) -> tuple[bool, str | None]:
        try:
            self._run_compose(["config", "--quiet"], compose_file=compose_file)
        except BridgeManagerError as exc:
            return False, str(exc)
        return True, None

    def _project_name(self, document: dict) -> str:
        configured = document.get("name")
        return str(configured) if configured else self.compose_dir.name

    def _runtime_containers(self, project_name: str) -> dict[str, dict]:
        try:
            client = docker.from_env()
            containers = client.containers.list(
                all=True,
                filters={"label": f"com.docker.compose.project={project_name}"},
            )
        except Exception as exc:
            raise BridgeManagerError(f"Cannot inspect Docker Compose containers: {exc}", 503) from exc
        runtime: dict[str, dict] = {}
        for container in containers:
            labels = container.labels or {}
            service = labels.get("com.docker.compose.service")
            if not service:
                continue
            runtime[service] = {
                "name": container.name,
                "state": container.status,
                "status": (container.attrs.get("State") or {}).get("Status") or container.status,
            }
        return runtime

    def _current_hash(self) -> str:
        content = self.compose_file.read_bytes() if self.compose_file.exists() else b"services: {}\n"
        return sha256(content).hexdigest()

    def mark_current_applied(self) -> None:
        self._ensure_paths()
        self.applied_hash_file.write_text(self._current_hash() + "\n", encoding="utf-8")
        os.chmod(self.applied_hash_file, 0o600)

    def _pending_apply(self) -> bool:
        try:
            applied = self.applied_hash_file.read_text(encoding="utf-8").strip()
        except OSError:
            return True
        return applied != self._current_hash()

    def project(self) -> BridgeProject:
        errors: list[str] = []
        try:
            document = self._load_document()
            self._validate_document(document)
        except BridgeManagerError as exc:
            return BridgeProject(
                node_ip=self.host.node_ip,
                compose_dir=str(self.compose_dir),
                compose_file=self.host.compose_file,
                compose_valid=False,
                pending_apply=True,
                errors=[str(exc)],
            )

        compose_valid, compose_error = self._compose_is_valid()
        if compose_error:
            errors.append(compose_error)
        try:
            runtime = self._runtime_containers(self._project_name(document))
        except BridgeManagerError as exc:
            runtime = {}
            errors.append(str(exc))

        bridges: list[BridgeDefinition] = []
        configured_names = {str(name) for name in document["services"]}
        for name, raw in document["services"].items():
            bridge = _parse_service(str(name), raw)
            state = runtime.get(str(name))
            if state:
                bridge.runtime_state = state["state"]
                bridge.runtime_status = state["status"]
                bridge.container_name = state["name"]
            bridges.append(bridge)

        orphans = [
            BridgeOrphan(
                name=state["name"],
                service=service,
                state=state["state"],
                status=state["status"],
            )
            for service, state in sorted(runtime.items())
            if service not in configured_names
        ]
        return BridgeProject(
            node_ip=self.host.node_ip,
            compose_dir=str(self.compose_dir),
            compose_file=self.host.compose_file,
            compose_valid=compose_valid,
            pending_apply=self._pending_apply(),
            services=bridges,
            orphans=orphans,
            errors=errors,
        )

    def _write_document(self, document: dict) -> None:
        self._validate_document(document)
        rendered = yaml.safe_dump(document, sort_keys=False, default_flow_style=False)
        self._ensure_paths()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.compose_file.name}.", suffix=".tmp", dir=self.compose_dir
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(rendered)
            os.chmod(temporary_path, 0o600)
            valid, error = self._compose_is_valid(temporary_path)
            if not valid:
                raise BridgeManagerError(f"Compose validation failed: {error}")
            if self.compose_file.exists():
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                shutil.copy2(
                    self.compose_file,
                    self.backups_dir / f"{self.compose_file.name}.{timestamp}",
                )
            os.replace(temporary_path, self.compose_file)
            os.chmod(self.compose_file, 0o600)
            backups = sorted(self.backups_dir.glob(f"{self.compose_file.name}.*"))
            for stale in backups[:-20]:
                stale.unlink()
        finally:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass

    def create(self, value: BridgeDefinitionInput) -> BridgeProject:
        validate_bridge_input(value)
        with self._locked():
            document = self._load_document()
            services = document["services"]
            if value.name in services:
                raise BridgeManagerError(f"Bridge already exists: {value.name}", 409)
            services[value.name] = _standard_service(value)
            self._write_document(document)
        return self.project()

    def update(self, current_name: str, value: BridgeDefinitionInput) -> BridgeProject:
        validate_bridge_input(value)
        with self._locked():
            document = self._load_document()
            services = document["services"]
            if current_name not in services:
                raise BridgeManagerError(f"Unknown bridge: {current_name}", 404)
            if not _parse_service(current_name, services[current_name]).managed:
                raise BridgeManagerError("Unsupported bridge definitions are read-only.", 409)
            if value.name != current_name and value.name in services:
                raise BridgeManagerError(f"Bridge already exists: {value.name}", 409)
            replacement = _standard_service(value)
            document["services"] = {
                (value.name if name == current_name else name): (
                    replacement if name == current_name else raw
                )
                for name, raw in services.items()
            }
            self._write_document(document)
        return self.project()

    def delete(self, name: str) -> BridgeProject:
        with self._locked():
            document = self._load_document()
            services = document["services"]
            if name not in services:
                raise BridgeManagerError(f"Unknown bridge: {name}", 404)
            if not _parse_service(name, services[name]).managed:
                raise BridgeManagerError("Unsupported bridge definitions are read-only.", 409)
            del services[name]
            self._write_document(document)
        return self.project()

    def service_action(self, name: str, action: str) -> BridgeOperationResult:
        if action not in {"start", "stop", "restart"}:
            raise BridgeManagerError(f"Unsupported bridge action: {action}")
        with self._locked():
            document = self._load_document()
            raw = document["services"].get(name)
            if raw is None:
                raise BridgeManagerError(f"Unknown bridge: {name}", 404)
            if not _parse_service(name, raw).managed:
                raise BridgeManagerError("Unsupported bridge definitions are read-only.", 409)
            result = self._run_compose([action, name], timeout=60)
        return BridgeOperationResult(
            message=f"Bridge {name} {action} completed.",
            stdout=result.stdout,
            stderr=result.stderr,
            project=self.project(),
        )

    def apply_project(self) -> BridgeOperationResult:
        with self._locked():
            document = self._load_document()
            self._validate_document(document)
            valid, error = self._compose_is_valid()
            if not valid:
                raise BridgeManagerError(f"Compose validation failed: {error}")
            if document["services"]:
                result = self._run_compose(
                    ["up", "-d", "--build", "--remove-orphans"], timeout=300
                )
            else:
                result = self._run_compose(["down", "--remove-orphans"], timeout=120)
            self.mark_current_applied()
        return BridgeOperationResult(
            message="Compose project applied.",
            stdout=result.stdout,
            stderr=result.stderr,
            project=self.project(),
        )

    def restart_project(self) -> BridgeOperationResult:
        with self._locked():
            document = self._load_document()
            if not document["services"]:
                return BridgeOperationResult(
                    message="Compose project has no configured services.", project=self.project()
                )
            result = self._run_compose(["restart"], timeout=120)
        return BridgeOperationResult(
            message="Compose project restarted without applying saved changes.",
            stdout=result.stdout,
            stderr=result.stderr,
            project=self.project(),
        )
