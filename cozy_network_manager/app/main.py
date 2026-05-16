from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from cozy_network_manager.app.api import head, minion
from cozy_network_manager.app.config import get_config
from cozy_network_manager.app.db.init_db import create_tables, sync_configured_nodes
from cozy_network_manager.app.db.session import SessionLocal
from cozy_network_manager.app.services.poller import Poller


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = get_config()
    poller: Poller | None = None
    if config.mode == "head":
        create_tables()
        with SessionLocal() as db:
            sync_configured_nodes(db, config)
        poller = Poller(config)
        poller.start()
    yield
    if poller:
        await poller.stop()


def create_app() -> FastAPI:
    config = get_config()
    app = FastAPI(title="Cozy Network Manager", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory="cozy_network_manager/app/static"), name="static")
    app.include_router(minion.router)
    if config.mode == "head":
        app.include_router(head.router)
    return app


app = create_app()

