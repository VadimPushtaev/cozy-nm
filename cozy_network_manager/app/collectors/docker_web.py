"""Recognize web protocols on Docker-published IPv4 TCP endpoints."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from ipaddress import IPv4Address

import httpx

from cozy_network_manager.app.schemas import CollectorMessage, PublicInterface

DISCOVERY_BUDGET = 4.0
REQUEST_TIMEOUT = 1.0
PROBE_CONCURRENCY = 8


@dataclass(frozen=True)
class WebCandidate:
    service: str
    address: str
    hostname: str
    port: int

    def url(self, scheme: str, *, probe: bool = False) -> str:
        host = self.address if probe else self.hostname
        suffix = "" if self.port == (443 if scheme == "https" else 80) else f":{self.port}"
        return f"{scheme}://{host}{suffix}/"


def web_candidates(
    attrs: dict, name: str, node_ip: str | None,
    public_hostname: str | None = None, public_ipv4: str | None = None,
) -> list[WebCandidate]:
    if (attrs.get("State") or {}).get("Status") != "running":
        return []
    candidates = set()
    for container_port, bindings in ((attrs.get("NetworkSettings") or {}).get("Ports") or {}).items():
        if not container_port.endswith("/tcp"):
            continue
        for binding in bindings or []:
            if not isinstance(binding, dict):
                continue
            try:
                port = int(binding.get("HostPort", ""))
                address = str(binding.get("HostIp") or "0.0.0.0")
                ip = IPv4Address(address)
            except (ValueError, TypeError):
                continue
            if not 1 <= port <= 65535 or ip.is_loopback:
                continue
            if address == "0.0.0.0":
                probe_address = node_ip or public_ipv4
                hostname = public_hostname or public_ipv4 or node_ip
            elif ip.is_global:
                probe_address = address
                hostname = public_hostname or address
            elif address == node_ip:
                probe_address = hostname = address
            else:
                continue
            if probe_address and hostname:
                candidates.add(WebCandidate(name, probe_address, hostname, port))
    return sorted(candidates, key=lambda item: (item.service, item.port, item.hostname))


async def _probe(client: httpx.AsyncClient, candidate: WebCandidate) -> PublicInterface | None:
    schemes = ("https", "http") if candidate.port == 443 else ("http", "https")
    for scheme in schemes:
        try:
            # Bound the whole request, including a peer slowly trickling headers.
            async with asyncio.timeout(REQUEST_TIMEOUT):
                authority = candidate.url(scheme).split("/")[2]
                async with client.stream(
                    "GET", candidate.url(scheme, probe=True),
                    headers={"Host": authority},
                    extensions={"sni_hostname": candidate.hostname},
                ) as response:
                    return PublicInterface(
                        service=candidate.service, url=candidate.url(scheme),
                        status="down" if response.status_code >= 500 else "up",
                    )
        except (httpx.HTTPError, TimeoutError):
            continue
    return None


async def discover_web_interfaces(
    candidates: list[WebCandidate],
) -> tuple[list[PublicInterface], list[CollectorMessage]]:
    if not candidates:
        return [], []
    found: list[PublicInterface] = []
    warnings: list[CollectorMessage] = []
    semaphore = asyncio.Semaphore(PROBE_CONCURRENCY)
    # This detects TLS-speaking services, including those with self-signed certs.
    # It does not certify their TLS configuration or external accessibility.
    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT, follow_redirects=False, trust_env=False, verify=False,
    ) as client:
        async def collect(candidate: WebCandidate):
            async with semaphore:
                result = await _probe(client, candidate)
                if result is not None:
                    found.append(result)

        try:
            async with asyncio.timeout(DISCOVERY_BUDGET):
                await asyncio.gather(*(collect(candidate) for candidate in candidates))
        except TimeoutError:
            warnings.append(CollectorMessage(
                source="docker", message="Web discovery exceeded its four-second budget; some ports were not checked",
            ))
    return sorted(found, key=lambda item: (item.service, item.url)), warnings
