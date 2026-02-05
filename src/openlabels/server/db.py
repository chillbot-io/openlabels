"""
Database connection and session management.
"""

import logging
from typing import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
    AsyncEngine,
)
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


# Global engine and session factory
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_db(
    database_url: str,
    pool_size: int = 5,
    max_overflow: int = 10,
) -> None:
    """
    Initialize database connection.

    Args:
        database_url: PostgreSQL connection URL (asyncpg driver)
        pool_size: Number of persistent connections in the pool.
            Configure via OPENLABELS_DATABASE__POOL_SIZE env var.
        max_overflow: Maximum overflow connections above pool_size.
            Configure via OPENLABELS_DATABASE__MAX_OVERFLOW env var.
    """
    global _engine, _session_factory

    _engine = create_async_engine(
        database_url,
        echo=False,
        pool_size=pool_size,
        max_overflow=max_overflow,
    )

    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def close_db() -> None:
    """Close database connection."""
    global _engine
    if _engine:
        await _engine.dispose()
        _engine = None


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session for dependency injection."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            logger.debug(f"Session error, rolling back: {e}")
            await session.rollback()
            raise


@asynccontextmanager
async def get_session_context() -> AsyncGenerator[AsyncSession, None]:
    """Get database session as context manager."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            logger.debug(f"Session error, rolling back: {e}")
            await session.rollback()
            raise


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get the session factory for direct use (e.g., WebSocket handlers)."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _session_factory


def get_engine() -> AsyncEngine | None:
    """
    Get the database engine for metrics and diagnostics.

    Returns:
        The AsyncEngine instance or None if not initialized.
        Access the sync pool via engine.sync_engine.pool for pool metrics.
    """
    return _engine


def run_migrations(revision: str, direction: str = "upgrade") -> None:
    """Run database migrations using Alembic."""
    from alembic import command
    from alembic.config import Config

    alembic_cfg = Config("alembic.ini")

    if direction == "upgrade":
        command.upgrade(alembic_cfg, revision)
    else:
        command.downgrade(alembic_cfg, revision)
