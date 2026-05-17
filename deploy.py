from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import textwrap
from ipaddress import ip_address
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "config.yml"
DEFAULT_REMOTE_DIR = "/root/cozy-nm"
PROJECT_NAME = "cozy-nm"
DEFAULT_STARTUP_TIMEOUT_SECONDS = 120
SSH_OPTIONS = [
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "ConnectTimeout=10",
]
EXCLUDES = [
    ".git",
    ".venv",
    ".cache",
    "__pycache__",
    ".pytest_cache",
]


def _minimal_config(path: Path) -> dict[str, Any]:
    config: dict[str, Any] = {"deployment": {"minions": []}}
    section: str | None = None
    current_list: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if indent == 0:
            section = None
            current_list = None
            if line == "deployment:":
                section = "deployment"
            elif ":" in line:
                key, value = line.split(":", 1)
                config[key] = value.strip()
            continue
        if section != "deployment":
            continue
        if indent == 2 and line.startswith("head:"):
            config["deployment"]["head"] = line.split(":", 1)[1].strip()
            current_list = None
        elif indent == 2 and line == "minions:":
            current_list = "minions"
        elif indent == 4 and current_list == "minions" and line.startswith("- "):
            config["deployment"]["minions"].append(line[2:].strip())
    return config


def load_config(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except Exception:
        return _minimal_config(path)
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def checked_ip(value: str) -> str:
    return str(ip_address(value))


def checked_port(value: Any, name: str) -> int:
    port = int(value)
    if port < 1 or port > 65535:
        raise ValueError(f"{name} must be a TCP port, got {port}")
    return port


def checked_remote_dir(value: str) -> str:
    path = value.rstrip("/")
    if not path.startswith("/") or path in {"", "/", "/root", "/home", "/tmp"}:
        raise ValueError(f"refusing unsafe remote deployment directory: {value!r}")
    return path


def deployment_targets(config: dict[str, Any]) -> tuple[str, list[str]]:
    deployment = config.get("deployment") or {}
    head = checked_ip(str(deployment.get("head") or ""))
    minions = [checked_ip(str(value)) for value in deployment.get("minions", [])]
    targets = sorted(set([head, *minions]), key=lambda value: ip_address(value))
    return head, targets


def run(args: list[str], *, stdin: Any = None) -> None:
    print(f"+ {shlex.join(args)}")
    subprocess.run(args, stdin=stdin, check=True, cwd=ROOT)


def ssh_args(host: str, command: str) -> list[str]:
    return ["ssh", *SSH_OPTIONS, f"root@{host}", command]


def ssh(host: str, command: str) -> None:
    run(ssh_args(host, command))


def explain_ssh_failure(host: str, stderr: str) -> None:
    print(f"Cannot reach root@{host} over SSH.", file=sys.stderr)
    if "Host key verification failed" in stderr or "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr:
        print(
            "The saved SSH host key does not match this machine. "
            "If this IP was reinstalled or reassigned, run:",
            file=sys.stderr,
        )
        print(f"  ssh-keygen -R {host}", file=sys.stderr)
        print(f"  ssh root@{host} true", file=sys.stderr)
        print("Then rerun: python deploy.py", file=sys.stderr)
    elif "Permission denied" in stderr:
        print(f"SSH auth failed. Check that root login/key auth works: ssh root@{host}", file=sys.stderr)
    elif stderr.strip():
        print(stderr.rstrip(), file=sys.stderr)


def verify_ssh(host: str) -> None:
    args = ssh_args(host, "true")
    print(f"+ {shlex.join(args)}")
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if result.returncode == 0:
        return
    explain_ssh_failure(host, result.stderr)
    raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)


def verify_ssh_hosts(hosts: list[str]) -> None:
    print("Checking SSH access before touching any host")
    for host in hosts:
        verify_ssh(host)


def remote_compose_helpers() -> str:
    return textwrap.dedent(
        """
        port_in_use() {
          port="$1"
          if command -v ss >/dev/null 2>&1; then
            ss -H -ltnp 2>/dev/null | awk -v port="$port" '$4 ~ "[:.]" port "$" { print }'
            return 0
          fi
          if command -v netstat >/dev/null 2>&1; then
            netstat -ltnp 2>/dev/null | awk -v port="$port" '$4 ~ "[:.]" port "$" { print }'
            return 0
          fi
          return 0
        }

        ensure_port_free() {
          port="$1"
          label="$2"
          lines="$(port_in_use "$port")"
          if [ -n "$lines" ]; then
            echo "Port $port for $label is already in use on $(hostname)." >&2
            echo "$lines" >&2
            exit 20
          fi
        }

        wait_healthy() {
          service="$1"
          deadline=$(( $(date +%s) + CNM_STARTUP_TIMEOUT ))
          while true; do
            cid="$(docker compose ps -q "$service" 2>/dev/null || true)"
            if [ -n "$cid" ]; then
              status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
              if [ "$status" = "healthy" ]; then
                return 0
              fi
              if [ "$status" = "exited" ] || [ "$status" = "dead" ]; then
                echo "$service exited while starting." >&2
                docker compose ps >&2 || true
                docker compose logs --tail=120 "$service" >&2 || true
                exit 21
              fi
            fi
            if [ "$(date +%s)" -ge "$deadline" ]; then
              echo "$service did not become healthy within ${CNM_STARTUP_TIMEOUT}s." >&2
              docker compose ps >&2 || true
              docker compose logs --tail=120 "$service" >&2 || true
              exit 22
            fi
            sleep 2
          done
        }
        """
    ).strip()


def remote_cleanup(host: str, remote_dir: str) -> None:
    quoted_dir = shlex.quote(remote_dir)
    command = textwrap.dedent(
        f"""
        set -eu
        if [ -d {quoted_dir} ]; then
          cd {quoted_dir}
          if [ -f docker-compose.yml ]; then
            COMPOSE_PROJECT_NAME={shlex.quote(PROJECT_NAME)} docker compose down --remove-orphans --timeout 15 || true
          fi
          if [ -f docker-compose.minion.yml ]; then
            COMPOSE_PROJECT_NAME={shlex.quote(PROJECT_NAME)} docker compose -f docker-compose.minion.yml down --remove-orphans --timeout 15 || true
          fi
        fi
        rm -rf {quoted_dir}
        mkdir -p {quoted_dir}
        """
    ).strip()
    ssh(host, command)


def copy_tree(host: str, remote_dir: str) -> None:
    tar_args = ["tar", *[f"--exclude={item}" for item in EXCLUDES], "-czf", "-", "."]
    ssh_args = [
        "ssh",
        *SSH_OPTIONS,
        f"root@{host}",
        f"tar -xzf - -C {shlex.quote(remote_dir)}",
    ]
    print(f"+ {shlex.join(tar_args)} | {shlex.join(ssh_args)}")
    with subprocess.Popen(tar_args, stdout=subprocess.PIPE, cwd=ROOT) as tar_proc:
        assert tar_proc.stdout is not None
        subprocess.run(ssh_args, stdin=tar_proc.stdout, check=True, cwd=ROOT)
        tar_proc.stdout.close()
        tar_return_code = tar_proc.wait()
    if tar_return_code != 0:
        raise subprocess.CalledProcessError(tar_return_code, tar_args)


def deploy_host(
    host: str,
    head: str,
    remote_dir: str,
    head_port: int,
    minion_port: int,
    postgres_port: int,
    startup_timeout: int,
) -> None:
    quoted_dir = shlex.quote(remote_dir)
    if host == head:
        command = textwrap.dedent(
            f"""
            set -eu
            cd {quoted_dir}
            export COMPOSE_PROJECT_NAME={shlex.quote(PROJECT_NAME)}
            export CNM_CONFIG_FILE=./config.yml
            export CNM_NODE_IP={shlex.quote(host)}
            export CNM_LISTEN_PORT={head_port}
            export CNM_MINION_PORT={minion_port}
            export CNM_POSTGRES_PORT={postgres_port}
            export CNM_STARTUP_TIMEOUT={startup_timeout}
            {remote_compose_helpers()}
            docker compose down --remove-orphans --timeout 15 || true
            ensure_port_free "$CNM_POSTGRES_PORT" postgres
            ensure_port_free "$CNM_LISTEN_PORT" head
            docker compose up -d --build postgres
            wait_healthy postgres
            docker compose up -d --build head
            """
        ).strip()
    else:
        command = textwrap.dedent(
            f"""
            set -eu
            cd {quoted_dir}
            export COMPOSE_PROJECT_NAME={shlex.quote(PROJECT_NAME)}
            export CNM_CONFIG_FILE=./config.yml
            export CNM_NODE_IP={shlex.quote(host)}
            export CNM_MINION_PORT={minion_port}
            docker compose -f docker-compose.minion.yml down --remove-orphans --timeout 15 || true
            ensure_port_free() {{
              port="$1"
              lines="$(ss -H -ltnp 2>/dev/null | awk -v port="$port" '$4 ~ "[:.]" port "$" {{ print }}' || true)"
              if [ -n "$lines" ]; then
                echo "Port $port for minion is already in use on $(hostname)." >&2
                echo "$lines" >&2
                exit 20
              fi
            }}
            ensure_port_free "$CNM_MINION_PORT"
            docker compose -f docker-compose.minion.yml up -d --build
            """
        ).strip()
    ssh(host, command)


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy Cozy Network Manager topology")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--remote-dir", default=DEFAULT_REMOTE_DIR)
    parser.add_argument("--postgres-port", type=int, default=int(os.getenv("CNM_POSTGRES_PORT", "15432")))
    parser.add_argument("--startup-timeout", type=int, default=DEFAULT_STARTUP_TIMEOUT_SECONDS)
    args = parser.parse_args()

    remote_dir = checked_remote_dir(args.remote_dir)
    config = load_config(args.config)
    head, targets = deployment_targets(config)
    head_port = checked_port(config.get("listen_port") or os.getenv("CNM_LISTEN_PORT", "8000"), "listen_port")
    minion_port = checked_port(config.get("minion_port") or os.getenv("CNM_MINION_PORT", "8000"), "minion_port")
    postgres_port = checked_port(args.postgres_port, "postgres_port")
    startup_timeout = int(args.startup_timeout)
    if startup_timeout < 10:
        raise ValueError("--startup-timeout must be at least 10 seconds")

    verify_ssh_hosts(targets)
    print(f"Deploying head {head} and minions {', '.join(targets)}")
    for host in targets:
        remote_cleanup(host, remote_dir)
        copy_tree(host, remote_dir)
        deploy_host(host, head, remote_dir, head_port, minion_port, postgres_port, startup_timeout)


if __name__ == "__main__":
    main()
