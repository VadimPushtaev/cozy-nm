# Cozy Network Manager

Cozy Network Manager is a self-hosted FastAPI tool for inspecting a private WireGuard VPN network. It runs as either a `head` dashboard or a read-only `minion` collector.

It is intentionally unauthenticated. Bind it only to trusted private VPN interfaces or localhost.

## Features

- Head mode with server-rendered dashboard, host WireGuard client inventory, node inventory, DNS mappings, port forwards, and warnings.
- Minion mode with `GET /health` and `GET /api/v1/snapshot`.
- PostgreSQL persistence for configured nodes, manual tags/notes, snapshots, DNS results, and warnings.
- Best-effort collectors for host metadata, network interfaces, WireGuard, Docker containers, and socat forwarding containers.
- YAML config with environment overrides.
- Docker and Docker Compose examples for head and minion deployments.

## Host visibility warning

The Docker examples bind host paths into the container so the app can inspect the host:

- `/etc/hostname`
- `/etc/os-release`
- `/etc/wireguard`
- `/proc`
- `/sys`
- `/var/run/docker.sock`

These mounts provide elevated visibility into the host. The Docker socket can expose broad host control to code running in the container, even though Cozy Network Manager only performs read-only inspection. Use this only on trusted machines inside your private VPN.

## Head quick start

Copy and edit the example config:

```bash
cp config.example.yml config.yml
```

Update `device_subnets`, `wireguard_clients_path`, `known_nodes`, and `dns.hostnames`, then mount that file in `docker-compose.yml` or change the compose volume from `config.example.yml` to `config.yml`.

Start the head:

```bash
docker compose up --build
```

Open `http://localhost:8000`.

## Minion quick start

On a VPN host that should report local data:

```bash
docker compose -f docker-compose.minion.yml up --build
```

The minion serves:

- `GET http://localhost:8000/health`
- `GET http://localhost:8000/api/v1/snapshot`

Point the head config at the minion's WireGuard-reachable URL, for example `http://10.46.0.2:8000`.

## Configuration

Primary config is YAML. Set `CNM_CONFIG=/config/config.yml` to choose the file. Environment overrides:

- `CNM_MODE=head|minion`
- `CNM_NODE_NAME=name`
- `CNM_LISTEN_HOST=0.0.0.0`
- `CNM_LISTEN_PORT=8000`
- `CNM_DATABASE_URL=postgresql+psycopg://user:pass@host:5432/db`
- `CNM_POLLING_INTERVAL_SECONDS=60`
- `CNM_DEVICE_SCAN_INTERVAL_SECONDS=10`
- `CNM_STALE_AFTER_SECONDS=300`
- `CNM_HOST_ROOT=/host`
- `CNM_WIREGUARD_CLIENTS_PATH=/host/wireguard/clients`
- `CNM_MINION_PORT=8000`

`wireguard_clients_path` points at the host directory containing client `.conf` and matching `.pub` files. The background scanner reads those configs every 10 seconds, matches each client public key against `wg show all dump`, pings the client IP, and checks `http://<client-ip>:8000/health` for the minion. `device_subnets` controls which client addresses are included. The example config defaults to `10.46.0.0/24`.

When running in Docker, the head container must be able to read the host client directory and host WireGuard state. The compose example mounts `/root/wireguard/clients` as read-only and runs the head service with the host network namespace plus `NET_ADMIN` so `wg show all dump` can inspect the host interface. If that is not acceptable for your deployment, run the head directly on the host instead.

The MVP only allows editing manual node tags and notes in the UI. Node identity, expected VPN IP, and minion URLs are config-owned.

## Local development

```bash
poetry install
poetry run pytest
CNM_CONFIG=config.example.yml poetry run uvicorn cozy_network_manager.app.main:app --reload
```

For local head development without Docker, set `CNM_DATABASE_URL` to a reachable PostgreSQL database.

## Notes

- WireGuard inspection uses `wg show all dump` when available and reports a warning when missing or denied.
- DNS inspection resolves only the configured `dns.hostnames`; it does not brute-force subdomains.
- Socat parsing is best-effort. Unknown destinations are displayed as unknown instead of failing collection.
