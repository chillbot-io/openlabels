"""
Pluggable storage backends for the Parquet catalog.

Provides a :class:`CatalogStorage` protocol and concrete implementations:

* :class:`LocalStorage` — local filesystem / NAS (Phase A)
* :class:`S3Storage` — S3 or S3-compatible object storage (Phase E)
* :class:`AzureBlobStorage` — Azure Blob Storage (Phase E)
"""

from __future__ import annotations

import io
import json
import logging
import os
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

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

    def list_files(self, prefix: str) -> list[str]:
        """List Parquet files (relative paths) under *prefix*."""
        ...

    def exists(self, path: str) -> bool:
        """Return True if the object at *path* exists."""
        ...

    def delete(self, path: str) -> None:
        """Delete the file or directory at *path*."""
        ...

    def read_bytes(self, path: str) -> bytes:
        """Read raw bytes from *path* (for JSON metadata, etc.)."""
        ...

    def write_bytes(self, path: str, data: bytes) -> None:
        """Write raw bytes to *path*."""
        ...

    @property
    def root(self) -> str:
        """Return the absolute root URI/path of the catalog."""
        ...


# ── Local filesystem ─────────────────────────────────────────────────

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

    def list_files(self, prefix: str) -> list[str]:
        base = self._resolve(prefix)
        if not base.is_dir():
            return []
        result: list[str] = []
        for p in sorted(base.rglob("*.parquet")):
            result.append(str(p.relative_to(self._base)))
        return result

    def exists(self, path: str) -> bool:
        return self._resolve(path).exists()

    def read_bytes(self, path: str) -> bytes:
        return self._resolve(path).read_bytes()

    def write_bytes(self, path: str, data: bytes) -> None:
        dest = self._resolve(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)

    def delete(self, path: str) -> None:
        target = self._resolve(path)
        if target.is_file():
            target.unlink()
        elif target.is_dir():
            import shutil
            shutil.rmtree(target)

    def read_json(self, path: str) -> dict[str, Any]:
        with open(self._resolve(path)) as f:
            return json.load(f)

    def write_json(self, path: str, data: dict[str, Any]) -> None:
        dest = self._resolve(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w") as f:
            json.dump(data, f, indent=2, default=str)


# ── S3 / S3-compatible ───────────────────────────────────────────────

class S3Storage:
    """S3-compatible object storage backend.

    Write path uses ``boto3``.  DuckDB reads S3 natively via the
    ``httpfs`` extension, so the engine only needs the catalog root URI.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "openlabels/catalog",
        region: str = "us-east-1",
        access_key: str = "",
        secret_key: str = "",
        endpoint_url: str | None = None,
    ) -> None:
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for S3 catalog storage. "
                "Install it with: pip install boto3"
            ) from exc

        self._bucket = bucket
        self._prefix = prefix.strip("/")

        kwargs: dict = {"region_name": region}
        if access_key and secret_key:
            kwargs["aws_access_key_id"] = access_key
            kwargs["aws_secret_access_key"] = secret_key
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url

        self._s3 = boto3.client("s3", **kwargs)
        self._endpoint_url = endpoint_url
        self._root = f"s3://{bucket}/{self._prefix}"

        logger.info("S3Storage catalog root: %s", self._root)

    @property
    def root(self) -> str:
        return self._root

    def _key(self, path: str) -> str:
        """Convert a relative catalog path to a full S3 key."""
        return f"{self._prefix}/{path}"

    def write_parquet(
        self,
        path: str,
        table: pa.Table,
        compression: str = "zstd",
    ) -> None:
        buf = io.BytesIO()
        pq.write_table(
            table,
            buf,
            compression=compression,
            row_group_size=100_000,
            write_statistics=True,
        )
        buf.seek(0)
        key = self._key(path)
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=buf.getvalue())
        logger.debug("Wrote %d rows to s3://%s/%s", table.num_rows, self._bucket, key)

    def read_parquet(self, path: str) -> pa.Table:
        key = self._key(path)
        response = self._s3.get_object(Bucket=self._bucket, Key=key)
        data = response["Body"].read()
        return pq.read_table(io.BytesIO(data))

    def list_partitions(self, prefix: str) -> list[str]:
        full_prefix = f"{self._prefix}/{prefix}".rstrip("/") + "/"
        paginator = self._s3.get_paginator("list_objects_v2")

        partitions: set[str] = set()
        for page in paginator.paginate(
            Bucket=self._bucket,
            Prefix=full_prefix,
            Delimiter="/",
        ):
            for cp in page.get("CommonPrefixes", []):
                name = cp["Prefix"][len(full_prefix):].rstrip("/")
                if name:
                    partitions.add(name)

        return sorted(partitions)

    def list_files(self, prefix: str) -> list[str]:
        full_prefix = f"{self._prefix}/{prefix}".rstrip("/") + "/"
        paginator = self._s3.get_paginator("list_objects_v2")

        files: list[str] = []
        for page in paginator.paginate(Bucket=self._bucket, Prefix=full_prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith(".parquet"):
                    # Return path relative to catalog root
                    rel_path = key[len(self._prefix) + 1:]
                    files.append(rel_path)
        return sorted(files)

    def exists(self, path: str) -> bool:
        key = self._key(path)
        try:
            self._s3.head_object(Bucket=self._bucket, Key=key)
            return True
        except self._s3.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise

    def read_bytes(self, path: str) -> bytes:
        key = self._key(path)
        response = self._s3.get_object(Bucket=self._bucket, Key=key)
        return response["Body"].read()

    def write_bytes(self, path: str, data: bytes) -> None:
        key = self._key(path)
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=data)

    def delete(self, path: str) -> None:
        key = self._key(path)
        # Check if it's a "directory" (prefix) — delete all objects under it
        full_prefix = key.rstrip("/") + "/"
        paginator = self._s3.get_paginator("list_objects_v2")

        objects_to_delete: list[dict] = []
        for page in paginator.paginate(Bucket=self._bucket, Prefix=full_prefix):
            for obj in page.get("Contents", []):
                objects_to_delete.append({"Key": obj["Key"]})

        if objects_to_delete:
            # Delete in batches of 1000 (S3 limit)
            for i in range(0, len(objects_to_delete), 1000):
                batch = objects_to_delete[i : i + 1000]
                self._s3.delete_objects(
                    Bucket=self._bucket,
                    Delete={"Objects": batch},
                )
        else:
            # Single object
            try:
                self._s3.delete_object(Bucket=self._bucket, Key=key)
            except Exception:
                pass


# ── Azure Blob Storage ───────────────────────────────────────────────

class AzureBlobStorage:
    """Azure Blob Storage backend.

    Write path uses the ``azure-storage-blob`` SDK.  DuckDB reads Azure
    natively via the ``azure`` extension.
    """

    def __init__(
        self,
        container: str,
        prefix: str = "openlabels/catalog",
        connection_string: str | None = None,
        account_name: str | None = None,
        account_key: str | None = None,
    ) -> None:
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            raise ImportError(
                "azure-storage-blob is required for Azure catalog storage. "
                "Install it with: pip install azure-storage-blob"
            ) from exc

        self._container_name = container
        self._prefix = prefix.strip("/")

        if connection_string:
            self._service = BlobServiceClient.from_connection_string(connection_string)
            self._connection_string = connection_string
        elif account_name and account_key:
            self._service = BlobServiceClient(
                account_url=f"https://{account_name}.blob.core.windows.net",
                credential=account_key,
            )
            self._connection_string = (
                f"DefaultEndpointsProtocol=https;"
                f"AccountName={account_name};"
                f"AccountKey={account_key};"
                f"EndpointSuffix=core.windows.net"
            )
        else:
            raise ValueError(
                "Azure storage requires connection_string or account_name+account_key"
            )

        self._container = self._service.get_container_client(container)
        self._root = f"az://{container}/{self._prefix}"
        logger.info("AzureBlobStorage catalog root: %s", self._root)

    @property
    def root(self) -> str:
        return self._root

    @property
    def connection_string(self) -> str:
        """Return the connection string for DuckDB azure extension config."""
        return self._connection_string

    def _blob_name(self, path: str) -> str:
        return f"{self._prefix}/{path}"

    def write_parquet(
        self,
        path: str,
        table: pa.Table,
        compression: str = "zstd",
    ) -> None:
        buf = io.BytesIO()
        pq.write_table(
            table,
            buf,
            compression=compression,
            row_group_size=100_000,
            write_statistics=True,
        )
        buf.seek(0)
        blob_name = self._blob_name(path)
        blob_client = self._container.get_blob_client(blob_name)
        blob_client.upload_blob(buf.getvalue(), overwrite=True)
        logger.debug("Wrote %d rows to az://%s/%s", table.num_rows, self._container_name, blob_name)

    def read_parquet(self, path: str) -> pa.Table:
        blob_name = self._blob_name(path)
        blob_client = self._container.get_blob_client(blob_name)
        data = blob_client.download_blob().readall()
        return pq.read_table(io.BytesIO(data))

    def list_partitions(self, prefix: str) -> list[str]:
        full_prefix = f"{self._prefix}/{prefix}".rstrip("/") + "/"
        partitions: set[str] = set()

        blobs = self._container.walk_blobs(name_starts_with=full_prefix, delimiter="/")
        for item in blobs:
            # BlobPrefix objects represent "directories"
            if hasattr(item, "prefix"):
                name = item.prefix[len(full_prefix):].rstrip("/")
                if name:
                    partitions.add(name)
            else:
                # It's a blob — extract the first path component after prefix
                rel = item.name[len(full_prefix):]
                if "/" in rel:
                    partitions.add(rel.split("/")[0])

        return sorted(partitions)

    def list_files(self, prefix: str) -> list[str]:
        full_prefix = f"{self._prefix}/{prefix}".rstrip("/") + "/"
        files: list[str] = []

        blobs = self._container.list_blobs(name_starts_with=full_prefix)
        for blob in blobs:
            if blob.name.endswith(".parquet"):
                rel_path = blob.name[len(self._prefix) + 1:]
                files.append(rel_path)

        return sorted(files)

    def exists(self, path: str) -> bool:
        blob_name = self._blob_name(path)
        blob_client = self._container.get_blob_client(blob_name)
        try:
            blob_client.get_blob_properties()
            return True
        except Exception:
            return False

    def read_bytes(self, path: str) -> bytes:
        blob_name = self._blob_name(path)
        blob_client = self._container.get_blob_client(blob_name)
        return blob_client.download_blob().readall()

    def write_bytes(self, path: str, data: bytes) -> None:
        blob_name = self._blob_name(path)
        blob_client = self._container.get_blob_client(blob_name)
        blob_client.upload_blob(data, overwrite=True)

    def delete(self, path: str) -> None:
        blob_name = self._blob_name(path)
        # Try to delete as a single blob first
        blob_client = self._container.get_blob_client(blob_name)
        try:
            blob_client.delete_blob()
            return
        except Exception:
            pass

        # Delete all blobs under the prefix (directory-like delete)
        full_prefix = blob_name.rstrip("/") + "/"
        blobs = self._container.list_blobs(name_starts_with=full_prefix)
        for blob in blobs:
            self._container.get_blob_client(blob.name).delete_blob()


# ── Factory ──────────────────────────────────────────────────────────

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

    if backend == "s3":
        s3 = catalog_settings.s3
        if not s3.bucket:
            raise ValueError("catalog.s3.bucket must be set when backend='s3'")
        return S3Storage(
            bucket=s3.bucket,
            prefix=s3.prefix,
            region=s3.region,
            access_key=s3.access_key,
            secret_key=s3.secret_key,
            endpoint_url=s3.endpoint_url,
        )

    if backend == "azure":
        az = catalog_settings.azure
        if not az.container:
            raise ValueError("catalog.azure.container must be set when backend='azure'")
        return AzureBlobStorage(
            container=az.container,
            prefix=az.prefix,
            connection_string=az.connection_string,
            account_name=az.account_name,
            account_key=az.account_key,
        )

    raise ValueError(f"Unsupported catalog backend: {backend!r}")
