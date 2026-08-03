from __future__ import annotations

from pathlib import Path
import subprocess

import pytest
import yaml

from cozy_network_manager.app.config import (
    AppConfig,
    BridgeHostConfig,
    BridgeManagementConfig,
)
from cozy_network_manager.app.schemas import BridgeDefinitionInput
from cozy_network_manager.app.services.bridges import BridgeManager, BridgeManagerError


def _manager(tmp_path: Path, monkeypatch, services: dict | None = None):
    compose_dir = tmp_path / "socat-docker"
    compose_dir.mkdir()
    compose_file = compose_dir / "docker-compose.yml"
    compose_file.write_text(
        yaml.safe_dump({"services": services or {}}, sort_keys=False),
        encoding="utf-8",
    )
    config = AppConfig(
        mode="minion",
        node_ip="10.46.0.1",
        bridges=BridgeManagementConfig(
            hosts=[BridgeHostConfig(node_ip="10.46.0.1", compose_dir=str(compose_dir))]
        ),
    )
    manager = BridgeManager(config)
    commands: list[list[str]] = []

    def run_compose(arguments, **kwargs):
        commands.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, "done\n", "")

    monkeypatch.setattr(manager, "_run_compose", run_compose)
    monkeypatch.setattr(manager, "_runtime_containers", lambda project: {})
    return manager, compose_file, commands


def _bridge(name: str = "rdp", listen_port: int = 13389) -> BridgeDefinitionInput:
    return BridgeDefinitionInput(
        name=name,
        listen_port=listen_port,
        target_host="10.46.0.2",
        target_port=3389,
    )


def test_project_lists_configured_bridge_even_without_container(tmp_path, monkeypatch):
    manager, _, _ = _manager(
        tmp_path,
        monkeypatch,
        services={
            "rdp": {
                "build": ".",
                "image": "socat-bridge:latest",
                "container_name": "rdp",
                "restart": "unless-stopped",
                "ports": ["13389:13389"],
                "environment": {
                    "LISTEN_PORT": "13389",
                    "TARGET_HOST": "10.46.0.2",
                    "TARGET_PORT": "3389",
                },
            }
        },
    )
    manager.mark_current_applied()

    project = manager.project()

    assert project.pending_apply is False
    assert project.compose_valid is True
    assert len(project.services) == 1
    assert project.services[0].name == "rdp"
    assert project.services[0].runtime_state is None
    assert project.services[0].managed is True


def test_save_and_apply_are_separate_operations(tmp_path, monkeypatch):
    manager, compose_file, commands = _manager(tmp_path, monkeypatch)
    manager.mark_current_applied()

    saved = manager.create(_bridge())

    assert saved.pending_apply is True
    assert not any(command[:1] == ["up"] for command in commands)
    service = yaml.safe_load(compose_file.read_text(encoding="utf-8"))["services"]["rdp"]
    assert service["ports"] == ["13389:13389"]
    assert service["environment"]["TARGET_PORT"] == "3389"

    result = manager.apply_project()

    assert ["up", "-d", "--build", "--remove-orphans"] in commands
    assert result.project is not None
    assert result.project.pending_apply is False
    assert (manager.compose_dir / ".dockerignore").read_text(encoding="utf-8") == ".cozy-nm/\n"


def test_duplicate_listen_port_is_rejected_without_replacing_file(tmp_path, monkeypatch):
    manager, compose_file, _ = _manager(tmp_path, monkeypatch)
    manager.create(_bridge("first", 13389))
    previous = compose_file.read_text(encoding="utf-8")

    with pytest.raises(BridgeManagerError, match="already used"):
        manager.create(_bridge("second", 13389))

    assert compose_file.read_text(encoding="utf-8") == previous


def test_bridge_can_be_edited_and_deleted_without_applying(tmp_path, monkeypatch):
    manager, compose_file, commands = _manager(tmp_path, monkeypatch)
    manager.create(_bridge())

    edited = manager.update(
        "rdp",
        BridgeDefinitionInput(
            name="windows-rdp",
            listen_port=23389,
            target_host="10.46.0.2",
            target_port=3389,
        ),
    )

    assert [bridge.name for bridge in edited.services] == ["windows-rdp"]
    assert edited.pending_apply is True
    assert "windows-rdp" in yaml.safe_load(compose_file.read_text(encoding="utf-8"))["services"]

    deleted = manager.delete("windows-rdp")

    assert deleted.services == []
    assert not any(command[0] in {"up", "down"} for command in commands)


def test_service_restart_is_scoped_to_configured_service(tmp_path, monkeypatch):
    manager, _, commands = _manager(tmp_path, monkeypatch)
    manager.create(_bridge())

    result = manager.service_action("rdp", "restart")

    assert ["restart", "rdp"] in commands
    assert result.message == "Bridge rdp restart completed."


def test_invalid_compose_is_not_installed(tmp_path, monkeypatch):
    manager, compose_file, _ = _manager(tmp_path, monkeypatch)
    previous = compose_file.read_text(encoding="utf-8")
    monkeypatch.setattr(manager, "_compose_is_valid", lambda compose_file=None: (False, "bad"))

    with pytest.raises(BridgeManagerError, match="Compose validation failed"):
        manager.create(_bridge())

    assert compose_file.read_text(encoding="utf-8") == previous


def test_unsupported_existing_service_is_visible_but_read_only(tmp_path, monkeypatch):
    manager, _, _ = _manager(
        tmp_path,
        monkeypatch,
        services={"custom": {"image": "alpine/socat", "command": "socat -V"}},
    )

    project = manager.project()

    assert project.services[0].managed is False
    assert "unsupported keys" in project.services[0].validation_error
    with pytest.raises(BridgeManagerError, match="read-only"):
        manager.delete("custom")


def test_empty_project_apply_runs_compose_down(tmp_path, monkeypatch):
    manager, _, commands = _manager(tmp_path, monkeypatch)

    result = manager.apply_project()

    assert ["down", "--remove-orphans"] in commands
    assert result.project is not None
    assert result.project.pending_apply is False


def test_runtime_orphans_are_reported(tmp_path, monkeypatch):
    manager, _, _ = _manager(tmp_path, monkeypatch)
    monkeypatch.setattr(
        manager,
        "_runtime_containers",
        lambda project: {
            "removed": {"name": "removed", "state": "running", "status": "running"}
        },
    )

    project = manager.project()

    assert [(orphan.service, orphan.name) for orphan in project.orphans] == [
        ("removed", "removed")
    ]
