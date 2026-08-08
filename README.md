# Cozy Network Manager

Cozy Network Manager is a self-hosted FastAPI dashboard for a private WireGuard network. A central **head** inventories WireGuard devices, polls host snapshots, resolves configured DNS names, stores history in PostgreSQL, and manages Socat port-forward projects through explicitly enabled **minions**.

The provided deployment runs everything in Docker. Keep the head and minion ports on trusted VPN addresses or loopback; the minion's inspection endpoints are intentionally not public-internet APIs.

## Architecture

- The **head** serves the HTML dashboard and read API, collects its own host snapshot, polls remote minions, scans WireGuard client configs, and refreshes DNS mappings.
- A **minion** exposes `GET /health` and `GET /api/v1/snapshot` for host inspection. On allowlisted bridge hosts it also exposes bearer-token-protected bridge-management endpoints.
- **PostgreSQL** stores nodes, snapshots, device state, DNS results, manual metadata, and warnings.
- The topology deployer starts PostgreSQL, the head, and a minion on the head host; other topology hosts run only a minion.

The head read API includes:

- `GET /api/v1/nodes`
- `GET /api/v1/devices`
- `GET /api/v1/nodes/{name}`
- `GET /api/v1/snapshots/{name}`

## Topology deployment

Prerequisites:

- Docker Engine with the Docker Compose v2 plugin on every target host.
- Python 3.12 or newer on the machine running `deploy.py`.
- Working `root@<VPN-IP>` SSH key access to every remote target.
- WireGuard already configured; Cozy-NM observes and manages services but does not create the VPN.

Create the local, git-ignored deployment files:

```bash
cp config.example.yml config.yml
```

Configure distinct head and minion ports, the VPN subnet, and all deployment targets. The head belongs in both `head` and `minions` because it also runs a local minion:

```yaml
listen_port: 8000
minion_port: 8001
device_subnets:
  - 10.46.0.0/24

deployment:
  head: 10.46.0.10
  minions:
    - 10.46.0.10
    - 10.46.0.20
    - 10.46.0.30

dns:
  domains:
    - example.com
  hostnames:
    - vpn.example.com
```

If bridge management is enabled, put a long random token in the git-ignored `.env` file:

```dotenv
CNM_BRIDGE_API_TOKEN=<long-random-value>
```

Deploy the whole topology:

```bash
python3 deploy.py
```

The deployer first verifies SSH access to every remote target. It then stops the existing Cozy-NM project, replaces `/root/cozy-nm`, copies the local tree—including `config.yml` and `.env`—and rebuilds the required services. Local topology targets are deployed without SSH. Expect brief downtime.

The replacement does not delete Docker volumes or host paths outside `/root/cozy-nm`, so PostgreSQL data, head authentication state, WireGuard files, and external bridge project directories survive redeployment.

Open the head at the configured VPN address and port, for example `http://10.46.0.10:8000`.

Useful deploy options:

```bash
python3 deploy.py --help
```

## Manual Docker Compose

For a loopback-only local stack using the example config:

```bash
docker compose up -d --build
```

This starts PostgreSQL, the head on `127.0.0.1:8000`, and a minion on `127.0.0.1:8001`. Open `http://localhost:8000`.

To bind a manually managed stack to a VPN address, provide the real config and node IP:

```bash
CNM_CONFIG_FILE=./config.yml CNM_NODE_IP=10.46.0.10 docker compose up -d --build
```

To run only a minion on another host:

```bash
CNM_CONFIG_FILE=./config.yml CNM_NODE_IP=10.46.0.20 docker compose -f docker-compose.minion.yml up -d --build
```

`CNM_NODE_IP` is the canonical node identity when set and controls the host-side bind address in the provided Compose files. `CNM_NODE_NAME` is a fallback identity for manual or compatibility configurations without a node IP.

## Configuration

Primary application configuration is YAML. `CNM_CONFIG` selects the file inside the running process; `CNM_CONFIG_FILE` selects the host file mounted by Docker Compose.

Important YAML settings:

- `listen_port`: head HTTP port. It must differ from `minion_port` when both run on the head host.
- `minion_port`: common HTTP port used by every minion; default `8001`.
- `deployment.head` and `deployment.minions`: VPN IP topology used for deployment, polling, and inventory.
- `device_subnets`: address ranges accepted from client configs and topology inventory.
- `wireguard_clients_path`: directory containing client `.conf` files and optional matching `.pub` public-key files.
- `wireguard_interfaces`: optional WireGuard interface filter; an empty list collects every interface.
- `polling_interval_seconds`: local and remote snapshot/DNS refresh interval.
- `device_scan_interval_seconds`: WireGuard device, ping, and minion-health scan interval.
- `stale_after_seconds`: maximum snapshot/handshake age considered online.
- `dns.domains` and `dns.hostnames`: DNS names inspected by the head.
- `bridges.hosts`: minion IPs and Compose directories enabled for bridge management.
- `head_auth_*`: head password state path, session lifetime, and secure-cookie behavior.

Application environment overrides:

- `CNM_CONFIG=/config/config.yml`
- `CNM_MODE=head|minion`
- `CNM_NODE_NAME=name`
- `CNM_NODE_IP=10.46.0.10`
- `CNM_LISTEN_PORT=8000`
- `CNM_DATABASE_URL=postgresql+psycopg://user:pass@host:5432/db`
- `CNM_POLLING_INTERVAL_SECONDS=60`
- `CNM_DEVICE_SCAN_INTERVAL_SECONDS=10`
- `CNM_STALE_AFTER_SECONDS=300`
- `CNM_HOST_ROOT=/host`
- `CNM_WIREGUARD_CLIENTS_PATH=/host/wireguard/clients`
- `CNM_MINION_PORT=8001`
- `CNM_PUBLIC_IPV4_URL=https://ifconfig.me/ip`
- `CNM_BRIDGE_API_TOKEN=shared-secret`
- `CNM_HEAD_AUTH_FILE=/var/lib/cozy-nm/auth/head-auth.json`
- `CNM_HEAD_AUTH_SESSION_DAYS=30`
- `CNM_HEAD_AUTH_COOKIE_SECURE=false`

Compose-only path and port overrides:

- `CNM_CONFIG_FILE=./config.yml`
- `CNM_POSTGRES_PORT=15432`
- `CNM_BRIDGE_COMPOSE_DIR=/root/socat-docker`
- `CNM_HEAD_AUTH_DIR=/root/.config/cozy-nm`

Manual Compose uses PostgreSQL loopback port `5432` unless overridden; `deploy.py` defaults it to `15432` to avoid colliding with a host PostgreSQL installation.

The provided Compose command binds the head with `CNM_NODE_IP` (or loopback when unset). A custom Uvicorn launch must pass its desired `--host` explicitly.

## Device and DNS inventory

Every `device_scan_interval_seconds`, the head:

1. Loads client addresses from `wireguard_clients_path`, restricted to `device_subnets`.
2. Adds topology nodes that do not have a local client config, including the head.
3. Matches public keys against `wg show all dump` and treats a recent handshake as connected.
4. Pings each VPN IP and checks `http://<VPN-IP>:<minion_port>/health`.

The displayed current public IP is derived from the WireGuard peer endpoint and is shown as current only while the peer is connected. Minion snapshots separately discover each host's public IPv4 through `CNM_PUBLIC_IPV4_URL`.

DNS inspection resolves only `A` records. For every `dns.domains` entry it checks the root and one random subdomain to detect wildcard DNS; `dns.hostnames` adds explicit names. Results are matched against VPN IPs, WireGuard peer endpoints, and public IPv4 values reported by snapshots.

## Head password authentication

The head starts without a password. Anyone who can reach it can use **Set password**, so set one promptly if the VPN contains users who should not administer the head.

- There is one shared password with a minimum length of eight characters.
- The password is stored as a salted scrypt hash; plaintext is never saved.
- Raw 256-bit session tokens are kept only in `HttpOnly`, `SameSite=Lax` browser cookies; only token hashes are persisted.
- Sessions last 30 days by default and survive container restarts.
- Failed password attempts receive an increasing per-IP delay, capped at 30 seconds.
- Changing the password signs out every other session and gives the requesting browser a new session.
- Removing the password immediately returns the head to passwordless mode.

Once configured, the head UI and API require a valid session. `/health`, login/setup routes, and static assets remain reachable as required for health checks and sign-in. Unsafe authenticated requests require a same-origin browser submission.

Docker Compose stores authentication state on the host at `/root/.config/cozy-nm/head-auth.json`, bind-mounted inside the head container. An SSH administrator can disable authentication immediately, without restarting Docker:

```bash
rm -f /root/.config/cozy-nm/head-auth.json
```

An existing but unreadable or malformed auth file fails closed with HTTP 503. If the head is served through HTTPS, set `CNM_HEAD_AUTH_COOKIE_SECURE=true`. With plain HTTP, rely on WireGuard to encrypt the browser connection.

## Minion and host security

Minion `GET /health` and `GET /api/v1/snapshot` are unauthenticated. Keep the minion bind private to loopback or WireGuard.

Bridge-management endpoints require `Authorization: Bearer <CNM_BRIDGE_API_TOKEN>`. The token is sent over HTTP, so its confidentiality depends on WireGuard unless HTTPS is added. `bridges.hosts` enables bridge management for the listed minion IP and directory; it is not a caller-IP access-control list. Anyone who can reach a minion and obtain the shared token can issue bridge commands.

The Docker examples mount host paths so collectors can inspect the host:

- `/etc/hostname`, `/etc/os-release`, `/etc/wireguard`, `/proc`, and `/sys`
- `/root/wireguard/clients`
- `/var/run/docker.sock`

The head's Docker socket bind is marked read-only, while minions receive a read-write bind because bridge actions control containers. A read-only socket mount does not make the Docker API read-only: access to the daemon socket can still amount to host-level control. The configured bridge project directory is also writable by the minion. Run these containers only on trusted hosts.

## Socat bridge management

Bridge hosts are an explicit management allowlist:

```yaml
bridges:
  hosts:
    - node_ip: 10.46.0.10
      compose_dir: /root/socat-docker
    - node_ip: 10.46.0.20
      compose_dir: /root/socat-docker
      compose_file: docker-compose.yml
```

The same non-empty `CNM_BRIDGE_API_TOKEN` must be available to the head and every bridge-enabled minion. The Compose examples mount `CNM_BRIDGE_COMPOSE_DIR`, which defaults to `/root/socat-docker`.

Each configured directory must already exist and contain a Dockerfile that builds a `socat-bridge:latest` image capable of using `LISTEN_PORT`, `TARGET_HOST`, and `TARGET_PORT`. The Compose file may initially be absent; the first UI save creates it.

The UI manages only a constrained service shape: service/container name, host listen port, IPv4 or DNS target, and target port. Unsupported service definitions remain visible and read-only. Saving validates and atomically rewrites the Compose YAML but does not change running containers. YAML comments and formatting are not preserved.

Before each replacement, the previous Compose file is copied to `.cozy-nm/backups`; the newest 20 backups are retained. Cozy-NM also records the last applied file hash there and ensures `.cozy-nm/` is excluded from the bridge Docker build context.

- **Apply project** runs `docker compose up -d --build --remove-orphans`, or `down --remove-orphans` when no services remain.
- **Restart project** restarts currently configured services without applying saved changes.
- Per-bridge **Start**, **Stop**, and **Restart** act on the current saved service.
- Deleted services remain as pending-removal orphans until the project is applied.

## Persistence

- PostgreSQL uses the `postgres-data` named Docker volume.
- Head authentication uses the host directory selected by `CNM_HEAD_AUTH_DIR`.
- Bridge Compose projects and backups live in the configured host directories.
- `config.yml` and `.env` live in the application directory and are recopied by `deploy.py`.

## Local development

```bash
poetry install
make pre-commit
CNM_CONFIG=config.example.yml poetry run uvicorn cozy_network_manager.app.main:app --reload
```

Head mode requires a reachable PostgreSQL database. For direct development, set `CNM_DATABASE_URL`; Uvicorn's `--host` and `--port` flags control the development server bind.

Collectors are best-effort. Missing commands, permissions, DNS failures, public-IP lookup failures, and unavailable minions are recorded as warnings instead of terminating the head.
