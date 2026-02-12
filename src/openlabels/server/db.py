"""
Database connection and session management.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
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
) -> None:
    """
    Initialize database connection.

    Args:
        database_url: PostgreSQL connection URL (asyncpg driver).
            Pool size and overflow are configured via settings
            (OPENLABELS_DATABASE__POOL_SIZE, OPENLABELS_DATABASE__MAX_OVERFLOW).
    """
    global _engine, _session_factory

    from openlabels.server.config import get_settings

    settings = get_settings()
    db_settings = settings.database

    logger.info(
        "Initializing database connection pool: "
        f"pool_size={db_settings.pool_size}, "
        f"max_overflow={db_settings.max_overflow}, "
        f"pool_recycle={db_settings.pool_recycle}s, "
        f"pool_pre_ping={db_settings.pool_pre_ping}, "
        f"pgbouncer_mode={db_settings.pgbouncer_mode}"
    )

    engine_kwargs: dict = {
        "echo": False,
        "pool_size": db_settings.pool_size,
        "max_overflow": db_settings.max_overflow,
        "pool_recycle": db_settings.pool_recycle,
        "pool_pre_ping": db_settings.pool_pre_ping,
        "pool_timeout": db_settings.pool_timeout,
    }

    # PgBouncer compatibility: disable prepared statements which don't
    # work with transaction-level pooling. Also set
    # statement_cache_size=0 in the asyncpg connect_args.
    if db_settings.pgbouncer_mode:
        engine_kwargs["connect_args"] = {
            "statement_cache_size": 0,
            "prepared_statement_cache_size": 0,
        }
        logger.info("PgBouncer mode enabled: prepared statements disabled")
    elif db_settings.statement_cache_size != 100:
        engine_kwargs["connect_args"] = {
            "statement_cache_size": db_settings.statement_cache_size,
        }

    _engine = create_async_engine(database_url, **engine_kwargs)

    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def close_db() -> None:
    """Close database connection."""
    global _engine, _session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
    _session_factory = None


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session for dependency injection."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:  # Intentionally broad: must rollback on any error before re-raising
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
        except Exception as e:  # Intentionally broad: must rollback on any error before re-raising
            logger.debug(f"Session error, rolling back: {e}")
            await session.rollback()
            raise


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get the session factory for direct use (e.g., WebSocket handlers)."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _session_factory


async def ensure_partitions(months_ahead: int = 3) -> None:
    """Create monthly range partitions for partitioned tables.

    Should be called on startup and periodically (e.g., weekly cron) to
    ensure partitions exist for upcoming months.  PostgreSQL will reject
    inserts into a partitioned table if no partition covers the row's
    partition key value and no DEFAULT partition exists.

    Args:
        months_ahead: Number of future months to pre-create partitions for.
    """
    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    sql = """
    DO $$
    DECLARE
        tbl TEXT;
        col TEXT;
        start_date DATE;
        end_date DATE;
        part_name TEXT;
        i INTEGER;
    BEGIN
        FOR tbl, col IN VALUES ('scan_results', 'scanned_at'),
                                ('file_access_events', 'event_time')
        LOOP
            FOR i IN 0..{months_ahead} LOOP
                start_date := date_trunc('month', CURRENT_DATE + (i || ' months')::interval);
                end_date   := start_date + '1 month'::interval;
                part_name  := tbl || '_' || to_char(start_date, 'YYYY_MM');

                IF NOT EXISTS (
                    SELECT 1 FROM pg_class WHERE relname = part_name
                ) THEN
                    EXECUTE format(
                        'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I '
                        'FOR VALUES FROM (%L) TO (%L)',
                        part_name, tbl, start_date, end_date
                    );
                END IF;
            END LOOP;
        END LOOP;
    END$$;
    """.replace("{months_ahead}", str(int(months_ahead)))

    from sqlalchemy import text

    async with _engine.begin() as conn:
        await conn.execute(text(sql))
    logger.info("Partition maintenance completed (months_ahead=%d)", months_ahead)


def run_migrations(revision: str, direction: str = "upgrade") -> None:
    """Run database migrations using Alembic."""
    from alembic import command
    from alembic.config import Config

    alembic_cfg = Config("alembic.ini")

    if direction == "upgrade":
        command.upgrade(alembic_cfg, revision)
    else:
        command.downgrade(alembic_cfg, revision)
