"""
Alembic environment configuration for OpenLabels.

Uses asyncpg for both migrations and application database access,
avoiding the need for a separate sync driver like psycopg2.
"""

import asyncio
import os
import sys
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import only db and models - avoid importing the full server package
# which has heavy dependencies (fastapi, etc.)
from openlabels.server.db import Base

# Import models module to register all models with Base.metadata
# This import has no side effects beyond registering the models
import openlabels.server.models  # noqa: F401

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set target metadata for autogenerate support
target_metadata = Base.metadata

# Override sqlalchemy.url from environment variable if set
# This allows flexible configuration without editing alembic.ini
database_url = os.environ.get("DATABASE_URL")
if database_url:
    # Ensure we use the asyncpg driver
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    config.set_main_option("sqlalchemy.url", database_url)
else:
    # Ensure the default URL from alembic.ini uses asyncpg
    url = config.get_main_option("sqlalchemy.url")
    if url and url.startswith("postgresql://"):
        config.set_main_option(
            "sqlalchemy.url",
            url.replace("postgresql://", "postgresql+asyncpg://", 1),
        )


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Include enum types in autogenerate
        compare_type=True,
        # Render SQL for enum creation
        render_as_batch=False,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    """Run migrations with a given connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Include enum types in autogenerate
        compare_type=True,
        # Render SQL for enum creation
        render_as_batch=False,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode using an async engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an async Engine
    and associate a connection with the context.
    """
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
