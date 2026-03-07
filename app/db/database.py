"""
Database layer for IR-Agent.

SQLAlchemy async engine — работает с SQLite (dev) и PostgreSQL (prod).
Переключается через DATABASE_URL в .env:
    SQLite:     sqlite+aiosqlite:///./ir_agent.db
    PostgreSQL: postgresql+asyncpg://user:pass@host/dbname
"""
from __future__ import annotations

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

logger = logging.getLogger("ir-agent")


def _safe_db_url(url: str) -> str:
    """Mask credentials in DATABASE_URL before logging. postgresql+asyncpg://user:pass@host/db → ...@host/db"""
    return re.sub(r"://[^@]+@", "://*****@", url)

# ── Engine ────────────────────────────────────────────────────────────────────

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    # SQLite не поддерживает pool_size, у PostgreSQL — по умолчанию 5
    **({} if settings.database_url.startswith("sqlite") else {"pool_size": 10, "max_overflow": 20}),
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ── Base ─────────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ── Session dependency ────────────────────────────────────────────────────────

@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager for database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """
    Run Alembic migrations on startup.

    Applies any pending migrations automatically — safe for both fresh installs
    (creates all tables) and upgrades (applies only new migrations).
    Uses create_all as fallback if Alembic is unavailable (test environments).
    """
    from app.db import models  # noqa: F401 — registers models with Base

    try:
        from alembic.config import Config
        from alembic import command
        import os

        alembic_cfg = Config(
            os.path.join(os.path.dirname(__file__), "..", "..", "alembic.ini")
        )
        # Run synchronously in a thread to avoid blocking the event loop
        # asyncio.get_running_loop() is the correct API in Python 3.10+ (get_event_loop deprecated)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: command.upgrade(alembic_cfg, "head"))
        logger.info("Database migrations applied: %s", _safe_db_url(settings.database_url))
    except Exception as e:
        logger.warning("Alembic migration failed (%s) — falling back to create_all", e)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created via create_all: %s", _safe_db_url(settings.database_url))


async def close_db() -> None:
    """Dispose engine on shutdown."""
    await engine.dispose()
    logger.info("Database connection pool closed")
