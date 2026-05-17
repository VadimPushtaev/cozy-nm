from __future__ import annotations

import asyncio
from contextlib import suppress

import httpx

from cozy_network_manager.app.collectors.snapshot import collect_snapshot
from cozy_network_manager.app.config import AppConfig
from cozy_network_manager.app.db.models import Node, WarningEvent
from cozy_network_manager.app.db.session import SessionLocal
from cozy_network_manager.app.schemas import Snapshot
from cozy_network_manager.app.services.devices import refresh_device_inventory
from cozy_network_manager.app.services.dns import refresh_dns_records
from cozy_network_manager.app.services.nodes import get_or_create_node, store_poll_error, store_snapshot


class Poller:
    def __init__(self, config: AppConfig):
        self.config = config
        self._tasks: list[asyncio.Task] = []
        self._stop = asyncio.Event()
        self._last_device_scan_error: str | None = None

    def start(self) -> None:
        self._tasks = [
            asyncio.create_task(self._run_polling()),
            asyncio.create_task(self._run_device_scans()),
        ]

    async def stop(self) -> None:
        self._stop.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with suppress(asyncio.CancelledError):
                await task

    async def _run_polling(self) -> None:
        while not self._stop.is_set():
            await self.poll_once()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop.wait(), self.config.polling_interval_seconds)

    async def _run_device_scans(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.to_thread(refresh_device_inventory, self.config)
                self._last_device_scan_error = None
            except Exception as exc:
                message = str(exc)
                if message != self._last_device_scan_error:
                    self._last_device_scan_error = message
                    await asyncio.to_thread(self._store_device_scan_error, message)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    self._stop.wait(), self.config.device_scan_interval_seconds
                )

    async def poll_once(self) -> None:
        await asyncio.to_thread(self._collect_local)
        async with httpx.AsyncClient(timeout=10) as client:
            for name, url in self.config.minion_targets():
                await self._poll_minion(client, name, url)
        await asyncio.to_thread(self._refresh_dns)

    def _collect_local(self) -> None:
        snapshot = collect_snapshot(self.config)
        with SessionLocal() as db:
            node = get_or_create_node(db, self.config.node_identifier(), "local")
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
        domains = self.config.dns_domains()
        hostnames = self.config.dns_hostnames()
        if not domains and not hostnames:
            return
        with SessionLocal() as db:
            refresh_dns_records(db, domains, hostnames)

    def _store_device_scan_error(self, message: str) -> None:
        safe_message = message.splitlines()[0][:500]
        with SessionLocal() as db:
            db.add(WarningEvent(source="device-scanner", message=safe_message))
            db.commit()
