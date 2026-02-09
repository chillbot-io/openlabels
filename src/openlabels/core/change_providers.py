"""
Change provider protocol and default implementations.

A ChangeProvider yields files that should be considered for scanning.
The orchestrator then runs each file through the adapter for content
reading, the inventory service for delta checks, and the classification
agents for entity detection.

Implementations
---------------
- ``FullWalkProvider`` — lists every file via the adapter (default)
- ``USNChangeProvider`` — Windows NTFS USN journal (Phase I)
- ``FanotifyChangeProvider`` — Linux fanotify (Phase I)
- ``SQSChangeProvider`` — S3 event notifications (Phase L)
- ``PubSubChangeProvider`` — GCS notifications (Phase L)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path as _Path
from typing import AsyncIterator, Optional, Protocol, runtime_checkable

import json
from typing import Any

from openlabels.adapters.base import FileInfo, FilterConfig, ReadAdapter

logger = logging.getLogger(__name__)


@runtime_checkable
class ChangeProvider(Protocol):
    """Yields files that *may* need scanning.

    The orchestrator still runs delta checks (inventory.should_scan_file)
    on each file, so a provider that is overly inclusive is safe — just
    slower.
    """

    async def changed_files(self) -> AsyncIterator[FileInfo]:
        """Yield files that may need scanning."""
        ...


class FullWalkProvider:
    """Default provider: list every file via the adapter.

    This is equivalent to the current behaviour of
    ``ScanOrchestrator._walk_files()`` and ``execute_scan_task()``.

    Parameters
    ----------
    adapter:
        A ReadAdapter (filesystem, sharepoint, onedrive, …).
    target:
        Path / site_id / URL handed to ``adapter.list_files()``.
    recursive:
        Walk subdirectories.
    filter_config:
        Optional filter for extensions, paths, size limits, etc.
    """

    def __init__(
        self,
        adapter: ReadAdapter,
        target: str,
        *,
        recursive: bool = True,
        filter_config: Optional[FilterConfig] = None,
    ) -> None:
        self._adapter = adapter
        self._target = target
        self._recursive = recursive
        self._filter_config = filter_config

    async def changed_files(self) -> AsyncIterator[FileInfo]:
        """Yield every file the adapter exposes."""
        async for file_info in self._adapter.list_files(
            self._target,
            recursive=self._recursive,
            filter_config=self._filter_config,
        ):
            yield file_info


# ── Real-time change providers (Phase I) ─────────────────────────────


class _StreamChangeProvider:
    """Base for change providers backed by a streaming event source.

    Buffers file-change events and yields them as ``FileInfo`` objects
    when ``changed_files()`` is called by the scan orchestrator.
    """

    def __init__(self) -> None:
        self._changed: dict[str, tuple[datetime, str]] = {}
        self._lock = asyncio.Lock()

    def notify(self, file_path: str, change_type: str = "modified") -> None:
        """Record a file change (called from EventStreamManager)."""
        self._changed[file_path] = (datetime.now(timezone.utc), change_type)

    async def changed_files(self) -> AsyncIterator[FileInfo]:
        """Yield files that changed since the last call, then clear."""
        async with self._lock:
            snapshot = dict(self._changed)
            self._changed.clear()

        for path, (modified, change_type) in snapshot.items():
            p = _Path(path)
            try:
                stat = p.stat()
                size = stat.st_size
            except OSError:
                size = 0

            yield FileInfo(
                path=path,
                name=p.name,
                size=size,
                modified=modified,
                change_type=change_type,
            )


class USNChangeProvider(_StreamChangeProvider):
    """Adapts USN journal events as a ``ChangeProvider`` for the scan pipeline.

    Wire to an ``EventStreamManager`` or ``USNJournalProvider`` that
    calls ``notify(file_path)`` on each relevant event.
    """

    pass


class FanotifyChangeProvider(_StreamChangeProvider):
    """Adapts fanotify events as a ``ChangeProvider`` for the scan pipeline.

    Wire to an ``EventStreamManager`` or ``FanotifyProvider`` that
    calls ``notify(file_path)`` on each relevant event.
    """

    pass


# ── Cloud change providers (Phase L) ─────────────────────────────────


class SQSChangeProvider:
    """Adapts S3 event notifications (via SQS) as a ``ChangeProvider``.

    Polls an SQS queue for S3 ``ObjectCreated`` / ``ObjectRemoved`` events
    and yields the affected keys as ``FileInfo`` objects.  Falls back to
    ETag-diff listing when SQS is not configured.

    Parameters
    ----------
    queue_url:
        SQS queue URL receiving S3 event notifications.
    bucket:
        S3 bucket name (for building ``s3://`` paths).
    region:
        AWS region for the SQS client.
    access_key / secret_key:
        Optional explicit credentials (falls back to env / IAM role).
    max_messages:
        Maximum messages per ``ReceiveMessage`` call (1–10).
    wait_time_seconds:
        Long-poll wait time (0–20 s).
    """

    def __init__(
        self,
        queue_url: str,
        bucket: str,
        region: str = "us-east-1",
        access_key: str = "",
        secret_key: str = "",
        max_messages: int = 10,
        wait_time_seconds: int = 5,
    ) -> None:
        self._queue_url = queue_url
        self._bucket = bucket
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._max_messages = min(max_messages, 10)
        self._wait_time_seconds = min(wait_time_seconds, 20)
        self._client: Any = None

    async def changed_files(self) -> AsyncIterator[FileInfo]:
        """Poll SQS and yield S3 keys that changed."""
        client = self._ensure_client()

        response = await asyncio.to_thread(
            lambda: client.receive_message(
                QueueUrl=self._queue_url,
                MaxNumberOfMessages=self._max_messages,
                WaitTimeSeconds=self._wait_time_seconds,
                MessageAttributeNames=["All"],
            )
        )

        messages = response.get("Messages", [])
        receipt_handles: list[str] = []

        for msg in messages:
            receipt_handles.append(msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", "{}"))
            except (json.JSONDecodeError, TypeError):
                continue

            # Handle SNS-wrapped messages
            if "Message" in body and "TopicArn" in body:
                try:
                    body = json.loads(body["Message"])
                except (json.JSONDecodeError, TypeError):
                    continue

            for record in body.get("Records", []):
                event_name = record.get("eventName", "")
                s3_info = record.get("s3", {})
                obj = s3_info.get("object", {})
                key = obj.get("key", "")
                if not key:
                    continue

                # URL-decode the key (S3 event notifications URL-encode keys)
                from urllib.parse import unquote_plus
                key = unquote_plus(key)

                size = obj.get("size", 0)
                etag = obj.get("eTag", "")

                if "ObjectCreated" in event_name:
                    change_type = "created"
                elif "ObjectRemoved" in event_name:
                    change_type = "deleted"
                else:
                    change_type = "modified"

                yield FileInfo(
                    path=f"s3://{self._bucket}/{key}",
                    name=key.rsplit("/", 1)[-1],
                    size=size,
                    modified=datetime.now(timezone.utc),
                    adapter="s3",
                    item_id=key,
                    change_type=change_type,
                    permissions={"etag": etag} if etag else None,
                )

        # Delete processed messages
        if receipt_handles:
            entries = [
                {"Id": str(i), "ReceiptHandle": rh}
                for i, rh in enumerate(receipt_handles)
            ]
            await asyncio.to_thread(
                lambda: client.delete_message_batch(
                    QueueUrl=self._queue_url, Entries=entries
                )
            )

    def _ensure_client(self) -> Any:
        if self._client is None:
            import boto3

            kwargs: dict[str, str] = {
                "service_name": "sqs",
                "region_name": self._region,
            }
            if self._access_key and self._secret_key:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            self._client = boto3.client(**kwargs)
        return self._client


class PubSubChangeProvider:
    """Adapts GCS notifications (via Pub/Sub) as a ``ChangeProvider``.

    Pulls messages from a Pub/Sub subscription that receives GCS
    ``OBJECT_FINALIZE`` / ``OBJECT_DELETE`` notifications and yields
    the affected blob names as ``FileInfo`` objects.

    Parameters
    ----------
    project:
        GCP project ID.
    subscription:
        Pub/Sub subscription name (short name, not full path).
    bucket:
        GCS bucket name (for building ``gs://`` paths).
    max_messages:
        Maximum messages per pull (default 100).
    credentials_path:
        Optional path to service account JSON key.
    """

    def __init__(
        self,
        project: str,
        subscription: str,
        bucket: str,
        max_messages: int = 100,
        credentials_path: str | None = None,
    ) -> None:
        self._project = project
        self._subscription = subscription
        self._bucket = bucket
        self._max_messages = max_messages
        self._credentials_path = credentials_path
        self._client: Any = None

    async def changed_files(self) -> AsyncIterator[FileInfo]:
        """Pull Pub/Sub messages and yield GCS blobs that changed."""
        client = self._ensure_client()
        subscription_path = client.subscription_path(
            self._project, self._subscription
        )

        response = await asyncio.to_thread(
            lambda: client.pull(
                request={
                    "subscription": subscription_path,
                    "max_messages": self._max_messages,
                },
                timeout=30,
            )
        )

        ack_ids: list[str] = []

        for msg in response.received_messages:
            ack_ids.append(msg.ack_id)
            attrs = dict(msg.message.attributes) if msg.message.attributes else {}

            event_type = attrs.get("eventType", "")
            blob_name = attrs.get("objectId", "")
            bucket_id = attrs.get("bucketId", self._bucket)

            if not blob_name:
                # Try parsing the message body as JSON
                try:
                    data = json.loads(msg.message.data.decode("utf-8"))
                    blob_name = data.get("name", "")
                    bucket_id = data.get("bucket", bucket_id)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

            if not blob_name:
                continue

            size = int(attrs.get("objectSize", attrs.get("size", "0")))
            generation = int(attrs.get("objectGeneration", "0")) or None

            if event_type == "OBJECT_FINALIZE":
                change_type = "created"
            elif event_type == "OBJECT_DELETE":
                change_type = "deleted"
            elif event_type == "OBJECT_METADATA_UPDATE":
                change_type = "modified"
            else:
                change_type = "modified"

            yield FileInfo(
                path=f"gs://{bucket_id}/{blob_name}",
                name=blob_name.rsplit("/", 1)[-1],
                size=size,
                modified=datetime.now(timezone.utc),
                adapter="gcs",
                item_id=blob_name,
                change_type=change_type,
                permissions={"generation": generation} if generation else None,
            )

        # Acknowledge processed messages
        if ack_ids:
            await asyncio.to_thread(
                lambda: client.acknowledge(
                    request={
                        "subscription": subscription_path,
                        "ack_ids": ack_ids,
                    }
                )
            )

    def _ensure_client(self) -> Any:
        if self._client is None:
            from google.cloud import pubsub_v1

            kwargs: dict = {}
            if self._credentials_path:
                from google.oauth2 import service_account
                credentials = service_account.Credentials.from_service_account_file(
                    self._credentials_path
                )
                kwargs["credentials"] = credentials
            self._client = pubsub_v1.SubscriberClient(**kwargs)
        return self._client
