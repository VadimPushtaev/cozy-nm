from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from cozy_network_manager.app.config import get_config


class Base(DeclarativeBase):
    pass


def _engine_url() -> str:
    return get_config().database_url


engine = create_engine(_engine_url(), pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

