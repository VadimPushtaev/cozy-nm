from __future__ import annotations

import asyncio
from contextlib import suppress

import httpx

from cozy_network_manager.app.collectors.snapshot import collect_snapshot
from cozy_network_manager.app.config import AppConfig
from cozy_network_manager.app.db.models import Node
from cozy_network_manager.app.db.session import SessionLocal
from cozy_network_manager.app.schemas import Snapshot
from cozy_network_manager.app.services.dns import refresh_dns_records
from cozy_network_manager.app.services.nodes import get_or_create_node, store_poll_error, store_snapshot


class Poller:
    def __init__(self, config: AppConfig):
        self.config = config
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    async def _run(self) -> None:
        while not self._stop.is_set():
            await self.poll_once()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop.wait(), self.config.polling_interval_seconds)

    async def poll_once(self) -> None:
        await asyncio.to_thread(self._collect_local)
        async with httpx.AsyncClient(timeout=10) as client:
            for known in self.config.known_nodes:
                if not known.minion_api_url:
                    continue
                await self._poll_minion(client, known.name, str(known.minion_api_url))
        await asyncio.to_thread(self._refresh_dns)

    def _collect_local(self) -> None:
        snapshot = collect_snapshot(self.config)
        with SessionLocal() as db:
            node = get_or_create_node(db, self.config.node_name, "local")
            store_snapshot(db, node, snapshot)

    async def _poll_minion(self, client: httpx.AsyncClient, name: str, url: str) -> None:
        snapshot_url = url.rstrip("/") + "/api/v1/snapshot"
        with SessionLocal() as db:
            node = db.query(Node).filter(Node.name == name).one()
        try:
            response = await client.get(snapshot_url)
            response.raise_for_status()
            snapshot = Snapshot.model_validate(response.json())
        except Exception as exc:
            with SessionLocal() as db:
                node = db.query(Node).filter(Node.name == name).one()
                store_poll_error(db, node, "poller", f"cannot poll {snapshot_url}: {exc}")
            return
        with SessionLocal() as db:
            node = db.query(Node).filter(Node.name == name).one()
            store_snapshot(db, node, snapshot)

    def _refresh_dns(self) -> None:
        hostnames = self.config.dns.hostnames
        if not hostnames:
            return
        with SessionLocal() as db:
            refresh_dns_records(db, hostnames)

