from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from uuid import uuid4

import dns.resolver
from sqlalchemy import desc

from cozy_network_manager.app.db.models import Device, DnsRecord, Node, SnapshotRecord


A_RECORD_TYPE = "A"


@dataclass
class DnsMapping:
    hostname: str
    record_type: str
    target: str
    matched_node: str | None
    outside_vpn: bool
    warning: str | None = None


def map_dns_answer(
    hostname: str,
    record_type: str,
    target: str,
    node_ip_map: dict[str, str],
) -> DnsMapping:
    matched = node_ip_map.get(target)
    outside = record_type in {"A", "AAAA"} and matched is None
    warning = "points to an IP not seen in VPN/public inventory" if outside else None
    return DnsMapping(hostname, record_type, target, matched, outside, warning)


def _record_target(answer) -> str:
    return str(answer).rstrip(".")


def _device_endpoint_ip(endpoint: str | None) -> str | None:
    if not endpoint:
        return None
    host = endpoint.rsplit(":", 1)[0].strip("[]")
    try:
        parsed = ip_address(host)
    except ValueError:
        return None
    return str(parsed) if parsed.is_global else None


def _latest_snapshot_public_ipv4(node: Node) -> str | None:
    latest = max(node.snapshots, key=lambda snapshot: snapshot.collected_at) if node.snapshots else None
    return (latest.snapshot.get("host") or {}).get("public_ipv4") if latest else None


def build_dns_ip_map(
    nodes: list[Node],
    devices: list[Device] | None = None,
    public_ipv4_by_node: dict[str, str] | None = None,
) -> dict[str, str]:
    ip_map = {node.expected_vpn_ip: node.name for node in nodes}
    for node in nodes:
        public_ipv4 = (
            public_ipv4_by_node.get(node.name)
            if public_ipv4_by_node is not None
            else _latest_snapshot_public_ipv4(node)
        )
        if public_ipv4:
            ip_map[public_ipv4] = node.name
    for device in devices or []:
        ip_map[device.ip] = device.name
        endpoint_ip = _device_endpoint_ip(device.endpoint)
        if endpoint_ip:
            ip_map.setdefault(endpoint_ip, device.name)
    return ip_map


def _resolve_hostname(
    resolver: dns.resolver.Resolver,
    hostname: str,
    node_ip_map: dict[str, str],
    *,
    display_hostname: str | None = None,
    warn_on_missing: bool,
) -> list[DnsMapping]:
    mappings: list[DnsMapping] = []
    label = display_hostname or hostname
    try:
        answers = resolver.resolve(hostname, A_RECORD_TYPE)
    except dns.resolver.NoAnswer:
        return mappings
    except dns.resolver.NXDOMAIN as exc:
        if warn_on_missing:
            mappings.append(
                DnsMapping(
                    hostname=label,
                    record_type=A_RECORD_TYPE,
                    target="",
                    matched_node=None,
                    outside_vpn=False,
                    warning=f"DNS lookup failed: {exc}",
                )
            )
        return mappings
    except Exception as exc:
        mappings.append(
            DnsMapping(
                hostname=label,
                record_type=A_RECORD_TYPE,
                target="",
                matched_node=None,
                outside_vpn=False,
                warning=f"DNS lookup failed: {exc}",
            )
        )
        return mappings
    for answer in answers:
        mappings.append(map_dns_answer(label, A_RECORD_TYPE, _record_target(answer), node_ip_map))
    return mappings


def resolve_hostnames(
    hostnames: list[str],
    nodes: list[Node],
    devices: list[Device] | None = None,
) -> list[DnsMapping]:
    resolver = dns.resolver.Resolver()
    node_ip_map = build_dns_ip_map(nodes, devices)
    mappings: list[DnsMapping] = []
    for hostname in sorted(set(hostnames)):
        mappings.extend(_resolve_hostname(resolver, hostname, node_ip_map, warn_on_missing=True))
    return mappings


def resolve_domains(
    domains: list[str],
    hostnames: list[str],
    nodes: list[Node],
    devices: list[Device] | None = None,
    public_ipv4_by_node: dict[str, str] | None = None,
) -> list[DnsMapping]:
    resolver = dns.resolver.Resolver()
    node_ip_map = build_dns_ip_map(nodes, devices, public_ipv4_by_node)
    mappings: list[DnsMapping] = []
    queried_hostnames = {hostname.strip().rstrip(".") for hostname in hostnames if hostname.strip()}

    for domain in sorted(set(domains)):
        domain = domain.strip().rstrip(".")
        if not domain:
            continue
        wildcard_probe = f"{uuid4().hex}.{domain}"
        mappings.extend(_resolve_hostname(resolver, domain, node_ip_map, warn_on_missing=True))
        mappings.extend(
            _resolve_hostname(
                resolver,
                wildcard_probe,
                node_ip_map,
                display_hostname=f"*.{domain}",
                warn_on_missing=False,
            )
        )

    for hostname in sorted(queried_hostnames):
        mappings.extend(_resolve_hostname(resolver, hostname, node_ip_map, warn_on_missing=True))

    return mappings


def _latest_public_ipv4_by_node(db, nodes: list[Node]) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in nodes:
        latest = (
            db.query(SnapshotRecord)
            .filter(SnapshotRecord.node_id == node.id)
            .order_by(desc(SnapshotRecord.collected_at))
            .first()
        )
        public_ipv4 = (latest.snapshot.get("host") or {}).get("public_ipv4") if latest else None
        if public_ipv4:
            values[node.name] = public_ipv4
    return values


def refresh_dns_records(
    db,
    domains: list[str] | None = None,
    hostnames: list[str] | None = None,
) -> list[DnsRecord]:
    nodes = db.query(Node).order_by(Node.name).all()
    devices = db.query(Device).order_by(Device.name).all()
    mappings = resolve_domains(
        domains or [],
        hostnames or [],
        nodes,
        devices,
        public_ipv4_by_node=_latest_public_ipv4_by_node(db, nodes),
    )
    db.query(DnsRecord).delete()
    records: list[DnsRecord] = []
    for mapping in mappings:
        record = DnsRecord(
            hostname=mapping.hostname,
            record_type=mapping.record_type,
            target=mapping.target,
            matched_node=mapping.matched_node,
            outside_vpn=mapping.outside_vpn,
            warning=mapping.warning,
            resolved_at=datetime.now(timezone.utc),
        )
        db.add(record)
        records.append(record)
    db.commit()
    return records
