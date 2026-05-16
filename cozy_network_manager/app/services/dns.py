from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import dns.resolver

from cozy_network_manager.app.db.models import DnsRecord, Node


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
    warning = "points outside known VPN nodes" if outside else None
    return DnsMapping(hostname, record_type, target, matched, outside, warning)


def resolve_hostnames(hostnames: list[str], nodes: list[Node]) -> list[DnsMapping]:
    resolver = dns.resolver.Resolver()
    node_ip_map = {node.expected_vpn_ip: node.name for node in nodes}
    mappings: list[DnsMapping] = []
    for hostname in hostnames:
        for record_type in ["A", "AAAA", "CNAME"]:
            try:
                answers = resolver.resolve(hostname, record_type)
            except dns.resolver.NoAnswer:
                continue
            except Exception as exc:
                mappings.append(
                    DnsMapping(
                        hostname=hostname,
                        record_type=record_type,
                        target="",
                        matched_node=None,
                        outside_vpn=False,
                        warning=f"DNS lookup failed: {exc}",
                    )
                )
                break
            for answer in answers:
                target = str(answer).rstrip(".")
                mappings.append(map_dns_answer(hostname, record_type, target, node_ip_map))
    return mappings


def refresh_dns_records(db, hostnames: list[str]) -> list[DnsRecord]:
    nodes = db.query(Node).order_by(Node.name).all()
    mappings = resolve_hostnames(hostnames, nodes)
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

