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

Update `device_subnets`, `wireguard_clients_path`, `deployment`, and `dns`, then run:

```bash
python deploy.py
```

`config.yml` is intentionally git-ignored so a real topology can stay local. A minimal deployment section looks like:

```yaml
deployment:
  head: 10.46.0.1
  minions:
    - 10.46.0.1
    - 10.46.0.5
    - 10.46.0.6
minion_port: 18081
```

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

For a shared topology config, pass the same config file and override only the local node name:

```bash
CNM_CONFIG_FILE=./config.yml CNM_NODE_NAME=ubuntu-8gb-hel1-1 docker compose -f docker-compose.minion.yml up --build
```

The minion serves:

- `GET http://localhost:8000/health`
- `GET http://localhost:8000/api/v1/snapshot`

List minion IPs under `deployment.minions`; the head derives each minion URL from that IP and `minion_port`. Set `minion_port` to a port that does not conflict with existing software on those hosts.

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
- `CNM_PUBLIC_IPV4_URL=https://ifconfig.me/ip`

`wireguard_clients_path` points at the host directory containing client `.conf` and matching `.pub` files. The background scanner reads those configs every 10 seconds, matches each client public key against `wg show all dump`, pings the client IP, and checks `http://<client-ip>:<minion_port>/health` for the minion. `device_subnets` controls which client addresses are included. The example config defaults to `10.46.0.0/24`.

`deployment` is the software placement plan. Device names are discovered from WireGuard client configs, so the deployment config only needs IPs.

`dns.domains` lists DNS zones to inspect, for example `pushtaev.ru`. The collector first tries an authoritative zone transfer so it can see all records. If the DNS provider refuses zone transfer, it falls back to the domain apex plus explicit `dns.hostnames` and records a warning. DNS `A` and `AAAA` records are matched against VPN IPs, WireGuard client endpoints, and the public IPv4 values reported by minions.

Minions report public IPv4 by calling `CNM_PUBLIC_IPV4_URL`, which defaults to `https://ifconfig.me/ip`.

When running in Docker, the head container must be able to read the host client directory and host WireGuard state. The compose example mounts `/root/wireguard/clients` as read-only and runs the head service with the host network namespace plus `NET_ADMIN` so `wg show all dump` can inspect the host interface. If that is not acceptable for your deployment, run the head directly on the host instead.

The MVP only allows editing manual node tags and notes in the UI. Node identity and expected VPN IP are config-owned.

## Local development

```bash
poetry install
poetry run pytest
CNM_CONFIG=config.example.yml poetry run uvicorn cozy_network_manager.app.main:app --reload
```

For local head development without Docker, set `CNM_DATABASE_URL` to a reachable PostgreSQL database.

## Notes

- WireGuard inspection uses `wg show all dump` when available and reports a warning when missing or denied.
- DNS inspection can only enumerate all records when the authoritative DNS servers allow zone transfer. Otherwise, add important names to `dns.hostnames`.
- Socat parsing is best-effort. Unknown destinations are displayed as unknown instead of failing collection.
