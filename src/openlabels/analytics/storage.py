"""
Pluggable storage backends for the Parquet catalog.

Provides a :class:`CatalogStorage` protocol and a concrete
:class:`LocalStorage` implementation.  Remote backends (S3, Azure)
are deferred to Phase E.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

import pyarrow as pa
import pyarrow.parquet as pq

logger = logging.getLogger(__name__)


@runtime_checkable
class CatalogStorage(Protocol):
    """Protocol for catalog storage backends."""

    def write_parquet(self, path: str, table: pa.Table, compression: str = "zstd") -> None:
        """Write an Arrow table as a Parquet file at *path* (relative to catalog root)."""
        ...

    def read_parquet(self, path: str) -> pa.Table:
        """Read a Parquet file and return an Arrow table."""
        ...

    def list_partitions(self, prefix: str) -> list[str]:
        """List immediate subdirectories under *prefix*."""
        ...

    def exists(self, path: str) -> bool:
        """Return True if the object at *path* exists."""
        ...

    def delete(self, path: str) -> None:
        """Delete the file or directory at *path*."""
        ...

    @property
    def root(self) -> str:
        """Return the absolute root URI/path of the catalog."""
        ...


class LocalStorage:
    """Local filesystem / NAS storage backend."""

    def __init__(self, base_path: str) -> None:
        self._base = Path(base_path)
        self._base.mkdir(parents=True, exist_ok=True)
        logger.info("LocalStorage catalog root: %s", self._base)

    @property
    def root(self) -> str:
        return str(self._base)

    def _resolve(self, path: str) -> Path:
        return self._base / path

    def write_parquet(
        self,
        path: str,
        table: pa.Table,
        compression: str = "zstd",
    ) -> None:
        dest = self._resolve(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        pq.write_table(
            table,
            dest,
            compression=compression,
            row_group_size=100_000,
            write_statistics=True,
        )
        logger.debug("Wrote %d rows to %s", table.num_rows, dest)

    def read_parquet(self, path: str) -> pa.Table:
        return pq.read_table(self._resolve(path))

    def list_partitions(self, prefix: str) -> list[str]:
        base = self._resolve(prefix)
        if not base.is_dir():
            return []
        return sorted(
            p.name for p in base.iterdir() if p.is_dir()
        )

    def exists(self, path: str) -> bool:
        return self._resolve(path).exists()

    def delete(self, path: str) -> None:
        target = self._resolve(path)
        if target.is_file():
            target.unlink()
        elif target.is_dir():
            import shutil
            shutil.rmtree(target)


def create_storage(catalog_settings) -> CatalogStorage:
    """Factory: build a storage backend from :class:`CatalogSettings`."""
    backend = catalog_settings.backend

    if backend == "local":
        path = catalog_settings.local_path
        if not path:
            raise ValueError(
                "catalog.local_path must be set when backend='local'"
            )
        return LocalStorage(path)

    # S3 and Azure deferred to Phase E
    raise ValueError(f"Unsupported catalog backend: {backend!r}")
