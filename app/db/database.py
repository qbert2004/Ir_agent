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
    Initialize the database schema on startup.

    Strategy (avoids the alembic-in-executor deadlock on Windows + Python 3.14
    + aiosqlite, where alembic's `asyncio.run()` inside `run_in_executor()`
    deadlocks against the running aiosqlite loop):

      1. Try `Base.metadata.create_all` via the live async engine — this is
         idempotent and safe for both fresh installs and existing databases.
      2. If alembic_version table is missing or empty, stamp it to current
         head so alembic CLI tools still work for future migrations.
      3. Skip running migrations on startup; pending migrations should be
         applied explicitly with `alembic upgrade head` from the CLI.
    """
    from app.db import models  # noqa: F401 — registers models with Base
    from sqlalchemy import text

    # Step 1: ensure all tables exist (idempotent)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Step 2: stamp alembic_version if needed (so CLI migrations still work)
    try:
        async with engine.begin() as conn:
            # Create alembic_version table if not exists
            await conn.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS alembic_version "
                    "(version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
                )
            )
            row = (await conn.execute(text("SELECT version_num FROM alembic_version"))).first()
            if row is None:
                # Discover current head from alembic scripts (sync, no DB I/O)
                from alembic.config import Config
                from alembic.script import ScriptDirectory
                import os

                alembic_cfg = Config(
                    os.path.join(os.path.dirname(__file__), "..", "..", "alembic.ini")
                )
                script = ScriptDirectory.from_config(alembic_cfg)
                head = script.get_current_head()
                if head:
                    await conn.execute(
                        text("INSERT INTO alembic_version (version_num) VALUES (:v)"),
                        {"v": head},
                    )
                    logger.info("Stamped alembic_version to head: %s", head)
    except Exception as e:
        logger.warning("alembic_version stamp skipped: %s", e)

    logger.info("Database ready: %s", _safe_db_url(settings.database_url))


async def close_db() -> None:
    """Dispose engine on shutdown."""
    await engine.dispose()
    logger.info("Database connection pool closed")
