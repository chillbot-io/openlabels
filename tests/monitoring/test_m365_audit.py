"""
Tests for Phase H: M365 audit provider, Graph webhook provider,
webhook endpoint, and operation mapping.

These tests validate:
- M365 operation → action mapping completeness
- Audit record parsing (file events, site filtering, time parsing)
- M365AuditProvider.collect() with mocked HTTP
- Subscription management (start, list, ensure)
- Content blob pagination
- GraphWebhookProvider delta query integration
- Webhook endpoint validation handshake
- Webhook clientState validation (constant-time)
- MonitoringSettings M365 config fields
- M365AuditProvider satisfies EventProvider protocol
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.monitoring.providers.base import EventProvider, RawAccessEvent
from openlabels.monitoring.providers.m365_audit import (
    M365AuditProvider,
    M365_OPERATION_MAP,
    EVENT_SOURCE,
    _parse_audit_record,
)


# =====================================================================
# Helpers
# =====================================================================


def _make_audit_record(
    operation: str = "FileAccessed",
    object_id: str = "https://contoso.sharepoint.com/sites/finance/Shared Documents/budget.xlsx",
    user_id: str = "user@contoso.com",
    creation_time: str = "2026-02-01T12:00:00Z",
    site_url: str = "https://contoso.sharepoint.com/sites/finance",
    item_type: str = "File",
    **kwargs,
) -> dict:
    """Create a minimal M365 audit record for testing."""
    record = {
        "Operation": operation,
        "ObjectId": object_id,
        "UserId": user_id,
        "CreationTime": creation_time,
        "SiteUrl": site_url,
        "ItemType": item_type,
        "UserKey": "i:0h.f|membership|100320022ec308a7@live.com",
        "SourceFileName": "budget.xlsx",
        "SourceRelativeUrl": "Shared Documents",
    }
    record.update(kwargs)
    return record


def _make_mock_response(
    status_code: int = 200,
    json_data=None,
    headers: dict | None = None,
) -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or []
    resp.text = ""
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import httpx
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp,
        )
    return resp


# =====================================================================
# Operation mapping tests
# =====================================================================


class TestM365OperationMap:
    """Tests for the M365 operation → action mapping."""

    def test_read_operations(self):
        """File access operations map to 'read'."""
        read_ops = [
            "FileAccessed", "FileAccessedExtended", "FilePreviewed",
            "FileDownloaded", "FileCopied",
            "FileSyncDownloadedFull", "FileSyncDownloadedPartial",
        ]
        for op in read_ops:
            assert M365_OPERATION_MAP[op] == "read", f"{op} should map to 'read'"

    def test_write_operations(self):
        """File modification operations map to 'write'."""
        write_ops = [
            "FileModified", "FileModifiedExtended", "FileUploaded",
            "FileCheckedOut", "FileCheckedIn", "FileRestored",
            "FileSyncUploadedFull", "FileSyncUploadedPartial",
        ]
        for op in write_ops:
            assert M365_OPERATION_MAP[op] == "write", f"{op} should map to 'write'"

    def test_delete_operations(self):
        """File deletion operations map to 'delete'."""
        delete_ops = [
            "FileDeleted", "FileRecycled",
            "FileDeletedFirstStageRecycleBin",
            "FileDeletedSecondStageRecycleBin",
            "FileVersionsAllDeleted",
        ]
        for op in delete_ops:
            assert M365_OPERATION_MAP[op] == "delete", f"{op} should map to 'delete'"

    def test_rename_operations(self):
        """File move/rename operations map to 'rename'."""
        rename_ops = ["FileMoved", "FileRenamed"]
        for op in rename_ops:
            assert M365_OPERATION_MAP[op] == "rename", f"{op} should map to 'rename'"

    def test_permission_operations(self):
        """Sharing operations map to 'permission_change'."""
        perm_ops = [
            "SharingSet", "SharingRevoked",
            "SharingInheritanceBroken", "SharingInheritanceReset",
            "AnonymousLinkCreated", "AnonymousLinkUpdated", "AnonymousLinkRemoved",
            "CompanyLinkCreated", "CompanyLinkRemoved",
            "AddedToSecureLink", "RemovedFromSecureLink",
        ]
        for op in perm_ops:
            assert M365_OPERATION_MAP[op] == "permission_change", (
                f"{op} should map to 'permission_change'"
            )

    def test_all_actions_are_valid_db_actions(self):
        """All mapped actions are in the valid DB enum set."""
        from openlabels.monitoring.harvester import _VALID_DB_ACTIONS

        for op, action in M365_OPERATION_MAP.items():
            assert action in _VALID_DB_ACTIONS, (
                f"{op} maps to '{action}' which is not a valid DB action"
            )

    def test_unmapped_operation_returns_none(self):
        """Unmapped operations are ignored in parsing."""
        record = _make_audit_record(operation="UnknownOperation")
        assert _parse_audit_record(record) is None


# =====================================================================
# Audit record parsing tests
# =====================================================================


class TestParseAuditRecord:
    """Tests for _parse_audit_record()."""

    def test_basic_file_access(self):
        """Parses a basic FileAccessed event correctly."""
        record = _make_audit_record()
        event = _parse_audit_record(record)

        assert event is not None
        assert event.action == "read"
        assert event.event_source == EVENT_SOURCE
        assert event.user_name == "user@contoso.com"
        assert event.file_path == (
            "https://contoso.sharepoint.com/sites/finance/"
            "Shared Documents/budget.xlsx"
        )

    def test_event_time_parsed(self):
        """CreationTime is parsed into event_time."""
        record = _make_audit_record(creation_time="2026-02-01T14:30:00Z")
        event = _parse_audit_record(record)

        assert event is not None
        assert event.event_time == datetime(
            2026, 2, 1, 14, 30, 0, tzinfo=timezone.utc,
        )

    def test_folder_items_skipped(self):
        """Folder-type items are ignored."""
        record = _make_audit_record(item_type="Folder")
        assert _parse_audit_record(record) is None

    def test_web_items_skipped(self):
        """Web-type items are ignored."""
        record = _make_audit_record(item_type="Web")
        assert _parse_audit_record(record) is None

    def test_site_url_filtering(self):
        """Events from non-monitored sites are filtered out."""
        record = _make_audit_record(
            site_url="https://contoso.sharepoint.com/sites/marketing",
        )
        monitored = ["https://contoso.sharepoint.com/sites/finance"]

        event = _parse_audit_record(record, monitored_site_urls=monitored)
        assert event is None

    def test_site_url_filtering_passes(self):
        """Events from monitored sites pass the filter."""
        record = _make_audit_record(
            site_url="https://contoso.sharepoint.com/sites/finance",
        )
        monitored = ["https://contoso.sharepoint.com/sites/finance"]

        event = _parse_audit_record(record, monitored_site_urls=monitored)
        assert event is not None

    def test_no_site_filter_passes_all(self):
        """Without site filtering, all events pass."""
        record = _make_audit_record(
            site_url="https://contoso.sharepoint.com/sites/random",
        )
        event = _parse_audit_record(record, monitored_site_urls=None)
        assert event is not None

    def test_fallback_file_path(self):
        """Falls back to SiteUrl+SourceRelativeUrl+SourceFileName."""
        record = _make_audit_record(object_id="")
        event = _parse_audit_record(record)

        assert event is not None
        assert "budget.xlsx" in event.file_path

    def test_no_file_path_skips(self):
        """Records with no identifiable file path are skipped."""
        record = _make_audit_record(object_id="")
        record["SiteUrl"] = ""
        record["SourceRelativeUrl"] = ""
        record["SourceFileName"] = ""

        assert _parse_audit_record(record) is None

    def test_user_key_as_user_sid(self):
        """UserKey is stored as user_sid."""
        record = _make_audit_record()
        event = _parse_audit_record(record)

        assert event is not None
        assert event.user_sid is not None

    def test_raw_dict_stored(self):
        """Full audit record is stored in the raw field."""
        record = _make_audit_record()
        event = _parse_audit_record(record)

        assert event is not None
        assert event.raw is record

    def test_invalid_creation_time_falls_back(self):
        """Invalid CreationTime falls back to now."""
        record = _make_audit_record(creation_time="not-a-date")
        event = _parse_audit_record(record)

        assert event is not None
        # Should be approximately now
        assert (datetime.now(timezone.utc) - event.event_time).total_seconds() < 5


# =====================================================================
# M365AuditProvider tests
# =====================================================================


class TestM365AuditProvider:
    """Tests for M365AuditProvider.collect() with mocked HTTP."""

    def test_is_event_provider(self):
        """M365AuditProvider satisfies the EventProvider protocol."""
        provider = M365AuditProvider("tenant", "client", "secret")
        assert isinstance(provider, EventProvider)

    def test_name(self):
        """Provider has correct name."""
        provider = M365AuditProvider("tenant", "client", "secret")
        assert provider.name == "m365_audit"

    @pytest.mark.asyncio
    async def test_collect_with_events(self):
        """collect() fetches content blobs and returns events."""
        provider = M365AuditProvider("tenant-id", "client-id", "secret")

        # Mock token acquisition
        provider._access_token = "mock-token"
        provider._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        provider._subscription_active = True
        provider._subscription_verified_at = datetime.now(timezone.utc)

        # Mock HTTP client (is_closed=False prevents _get_client from replacing it)
        mock_client = AsyncMock()
        mock_client.is_closed = False
        provider._client = mock_client

        # Mock content listing response
        content_list_resp = _make_mock_response(
            json_data=[
                {"contentUri": "https://manage.office.com/content/blob1"},
                {"contentUri": "https://manage.office.com/content/blob2"},
            ],
            headers={},
        )

        # Mock content blob response
        blob_resp = _make_mock_response(
            json_data=[_make_audit_record()],
        )

        mock_client.request = AsyncMock(side_effect=[content_list_resp, blob_resp, blob_resp])

        events = await provider.collect()

        assert len(events) == 2  # 1 event per blob
        assert all(e.event_source == "m365_audit" for e in events)

    @pytest.mark.asyncio
    async def test_collect_empty(self):
        """collect() returns empty list when no content blobs."""
        provider = M365AuditProvider("tenant-id", "client-id", "secret")
        provider._access_token = "mock-token"
        provider._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        provider._subscription_active = True

        mock_client = AsyncMock()
        mock_client.is_closed = False
        provider._client = mock_client

        empty_resp = _make_mock_response(json_data=[])
        mock_client.request = AsyncMock(return_value=empty_resp)

        events = await provider.collect()
        assert events == []

    @pytest.mark.asyncio
    async def test_collect_handles_blob_failure(self):
        """collect() continues if a single blob fetch fails."""
        provider = M365AuditProvider("tenant-id", "client-id", "secret")
        provider._access_token = "mock-token"
        provider._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        provider._subscription_active = True
        provider._subscription_verified_at = datetime.now(timezone.utc)

        mock_client = AsyncMock()
        mock_client.is_closed = False
        provider._client = mock_client

        content_list_resp = _make_mock_response(
            json_data=[
                {"contentUri": "https://manage.office.com/content/blob1"},
                {"contentUri": "https://manage.office.com/content/blob2"},
            ],
        )

        good_blob = _make_mock_response(json_data=[_make_audit_record()])
        bad_blob = _make_mock_response(status_code=500)

        mock_client.request = AsyncMock(
            side_effect=[content_list_resp, bad_blob, good_blob],
        )

        events = await provider.collect()
        # One blob failed, one succeeded
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_ensure_subscription_starts_if_inactive(self):
        """_ensure_subscription() starts subscription when not active."""
        provider = M365AuditProvider("tenant-id", "client-id", "secret")
        provider._access_token = "mock-token"
        provider._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        mock_client = AsyncMock()
        mock_client.is_closed = False

        # List subscriptions — returns empty (no active sub)
        list_resp = _make_mock_response(json_data=[])
        # Start subscription — success
        start_resp = _make_mock_response(status_code=200, json_data={})

        mock_client.request = AsyncMock(side_effect=[list_resp, start_resp])

        await provider._ensure_subscription(mock_client)

        assert provider._subscription_active is True
        assert mock_client.request.call_count == 2

    @pytest.mark.asyncio
    async def test_ensure_subscription_skips_if_active(self):
        """_ensure_subscription() is a no-op when recently verified."""
        provider = M365AuditProvider("tenant-id", "client-id", "secret")
        provider._subscription_active = True
        provider._subscription_verified_at = datetime.now(timezone.utc)

        mock_client = AsyncMock()
        await provider._ensure_subscription(mock_client)

        mock_client.request.assert_not_called()


# =====================================================================
# Content pagination tests
# =====================================================================


class TestContentPagination:
    """Tests for _list_content() pagination."""

    @pytest.mark.asyncio
    async def test_single_page(self):
        """Single page of content blobs."""
        provider = M365AuditProvider("tenant-id", "client-id", "secret")
        provider._access_token = "mock-token"
        provider._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        mock_client = AsyncMock()
        mock_client.is_closed = False
        resp = _make_mock_response(
            json_data=[
                {"contentUri": "https://manage.office.com/content/blob1"},
            ],
            headers={},
        )
        mock_client.request = AsyncMock(return_value=resp)

        start = datetime(2026, 2, 1, tzinfo=timezone.utc)
        end = datetime(2026, 2, 2, tzinfo=timezone.utc)
        uris = await provider._list_content(mock_client, start, end)

        assert uris == ["https://manage.office.com/content/blob1"]

    @pytest.mark.asyncio
    async def test_multi_page(self):
        """Multiple pages are followed via NextPageUri header."""
        provider = M365AuditProvider("tenant-id", "client-id", "secret")
        provider._access_token = "mock-token"
        provider._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        mock_client = AsyncMock()
        mock_client.is_closed = False

        page1 = _make_mock_response(
            json_data=[{"contentUri": "https://manage.office.com/content/blob1"}],
            headers={"NextPageUri": "https://manage.office.com/page2"},
        )
        page2 = _make_mock_response(
            json_data=[{"contentUri": "https://manage.office.com/content/blob2"}],
            headers={},
        )
        mock_client.request = AsyncMock(side_effect=[page1, page2])

        start = datetime(2026, 2, 1, tzinfo=timezone.utc)
        end = datetime(2026, 2, 2, tzinfo=timezone.utc)
        uris = await provider._list_content(mock_client, start, end)

        assert len(uris) == 2


# =====================================================================
# GraphWebhookProvider tests
# =====================================================================


class TestGraphWebhookProvider:
    """Tests for GraphWebhookProvider."""

    def test_is_event_provider(self):
        """GraphWebhookProvider satisfies the EventProvider protocol."""
        from openlabels.monitoring.providers.graph_webhook import GraphWebhookProvider

        mock_client = MagicMock()
        provider = GraphWebhookProvider(mock_client)
        assert isinstance(provider, EventProvider)

    def test_name(self):
        """Provider has correct name."""
        from openlabels.monitoring.providers.graph_webhook import GraphWebhookProvider

        mock_client = MagicMock()
        provider = GraphWebhookProvider(mock_client)
        assert provider.name == "graph_webhook"

    @pytest.mark.asyncio
    async def test_collect_empty_when_no_notifications(self):
        """collect() returns [] when no pending notifications."""
        from openlabels.monitoring.providers.graph_webhook import GraphWebhookProvider

        mock_client = MagicMock()
        provider = GraphWebhookProvider(mock_client)

        # Patch at the module where it's imported in graph_webhook.py
        with patch(
            "openlabels.monitoring.notification_queue.drain_graph_notifications",
            return_value=[],
        ):
            events = await provider.collect()

        assert events == []

    @pytest.mark.asyncio
    async def test_collect_runs_delta_for_notifications(self):
        """collect() runs delta queries for queued notifications."""
        from openlabels.monitoring.providers.graph_webhook import GraphWebhookProvider

        mock_client = AsyncMock()
        # get_with_delta returns (items, is_delta)
        mock_client.get_with_delta = AsyncMock(return_value=([
            {
                "name": "report.xlsx",
                "parentReference": {"path": "/drive/root:/Documents"},
                "lastModifiedDateTime": "2026-02-01T12:00:00Z",
                "lastModifiedBy": {"user": {"email": "user@contoso.com"}},
            },
        ], True))

        provider = GraphWebhookProvider(mock_client)

        notifications = [{"resource": "/drives/drive-abc/root"}]
        with patch(
            "openlabels.monitoring.notification_queue.drain_graph_notifications",
            return_value=notifications,
        ):
            events = await provider.collect()

        assert len(events) == 1
        assert events[0].file_path == "/Documents/report.xlsx"
        assert events[0].action == "write"
        assert events[0].event_source == "graph_webhook"
        assert events[0].user_name == "user@contoso.com"

    @pytest.mark.asyncio
    async def test_collect_skips_folders(self):
        """Folder items from delta are skipped."""
        from openlabels.monitoring.providers.graph_webhook import GraphWebhookProvider

        mock_client = AsyncMock()
        mock_client.get_with_delta = AsyncMock(return_value=([
            {
                "name": "My Folder",
                "folder": {"childCount": 5},
                "parentReference": {"path": "/drive/root:"},
                "lastModifiedDateTime": "2026-02-01T12:00:00Z",
            },
        ], True))

        provider = GraphWebhookProvider(mock_client)

        with patch(
            "openlabels.monitoring.notification_queue.drain_graph_notifications",
            return_value=[{"resource": "/drives/drive-abc/root"}],
        ):
            events = await provider.collect()

        assert events == []

    @pytest.mark.asyncio
    async def test_subscribe(self):
        """subscribe() creates a Graph subscription."""
        from openlabels.monitoring.providers.graph_webhook import GraphWebhookProvider

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value={
            "id": "sub-123",
            "resource": "/drives/drive-abc/root",
        })

        provider = GraphWebhookProvider(
            mock_client,
            webhook_url="https://example.com/api/v1/webhooks/graph",
            client_state="secret",
        )

        sub_id = await provider.subscribe("drive-abc")
        assert sub_id == "sub-123"
        assert "sub-123" in provider._subscriptions

        # Verify the POST body
        call_kwargs = mock_client.post.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["changeType"] == "updated"
        assert body["resource"] == "/drives/drive-abc/root"
        assert body["clientState"] == "secret"


# =====================================================================
# Webhook endpoint tests
# =====================================================================


class TestWebhookEndpoint:
    """Tests for the webhook endpoints (routes/webhooks.py).

    FastAPI TestClient tests are skipped if fastapi is not installed.
    The notification queue tests use the lightweight notification_queue
    module directly and always run.
    """

    def test_drain_graph_notifications(self):
        """drain_graph_notifications() drains the graph queue."""
        from openlabels.monitoring.notification_queue import (
            _graph_notifications,
            drain_graph_notifications,
            push_graph_notification,
        )

        _graph_notifications.clear()
        push_graph_notification({"test": True})
        push_graph_notification({"test": False})

        result = drain_graph_notifications()
        assert len(result) == 2
        assert len(_graph_notifications) == 0

    def test_push_m365_notification(self):
        """push_m365_notification() adds to the M365 queue."""
        from openlabels.monitoring.notification_queue import (
            _m365_notifications,
            push_m365_notification,
        )

        _m365_notifications.clear()
        push_m365_notification({"content": "blob1"})
        assert len(_m365_notifications) == 1
        assert _m365_notifications[0]["content"] == "blob1"
        _m365_notifications.clear()

    @pytest.fixture(autouse=True)
    def _skip_without_fastapi(self):
        """Skip FastAPI-dependent tests if fastapi is not installed."""
        pass

    def test_validation_handshake_m365(self):
        """M365 webhook echoes back validationToken."""
        fastapi = pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from openlabels.server.routes.webhooks import router

        app = fastapi.FastAPI()
        app.include_router(router)

        with TestClient(app) as client:
            resp = client.post(
                "/webhooks/m365?validationToken=abc123",
            )
            assert resp.status_code == 200
            assert resp.text == "abc123"
            assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    def test_validation_handshake_graph(self):
        """Graph webhook echoes back validationToken."""
        fastapi = pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from openlabels.server.routes.webhooks import router

        app = fastapi.FastAPI()
        app.include_router(router)

        with TestClient(app) as client:
            resp = client.post(
                "/webhooks/graph?validationToken=xyz789",
            )
            assert resp.status_code == 200
            assert resp.text == "xyz789"

    def test_m365_notification_accepted(self):
        """Valid M365 notification is accepted."""
        fastapi = pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from openlabels.server.routes import webhooks
        from openlabels.monitoring.notification_queue import _m365_notifications

        app = fastapi.FastAPI()
        app.include_router(webhooks.router)

        _m365_notifications.clear()

        with patch("openlabels.server.routes.webhooks.get_settings") as mock_settings:
            mock_settings.return_value.monitoring.webhook_client_state = "my-secret"

            with TestClient(app) as client:
                resp = client.post(
                    "/webhooks/m365",
                    json=[{
                        "clientState": "my-secret",
                        "contentUri": "https://manage.office.com/content/blob1",
                    }],
                )
                assert resp.status_code == 200

        _m365_notifications.clear()

    def test_m365_notification_bad_client_state(self):
        """M365 notification with wrong clientState is rejected (silently)."""
        fastapi = pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from openlabels.server.routes import webhooks
        from openlabels.monitoring.notification_queue import _m365_notifications

        app = fastapi.FastAPI()
        app.include_router(webhooks.router)

        _m365_notifications.clear()

        with patch("openlabels.server.routes.webhooks.get_settings") as mock_settings:
            mock_settings.return_value.monitoring.webhook_client_state = "correct-secret"

            with TestClient(app) as client:
                resp = client.post(
                    "/webhooks/m365",
                    json=[{
                        "clientState": "wrong-secret",
                        "contentUri": "https://manage.office.com/content/blob1",
                    }],
                )
                # Returns 200 (don't leak validation info) but doesn't queue
                assert resp.status_code == 200

            # Notification was NOT queued
            assert len(_m365_notifications) == 0


# =====================================================================
# MonitoringSettings M365 config tests
# =====================================================================


class TestMonitoringSettingsM365:
    """Tests for M365-specific MonitoringSettings fields."""

    def test_m365_defaults(self):
        """M365 fields have correct defaults."""
        from openlabels.server.config import MonitoringSettings

        s = MonitoringSettings()
        assert s.m365_harvest_interval_seconds == 300
        assert s.m365_site_urls == []
        assert s.webhook_enabled is False
        assert s.webhook_client_state == ""

    def test_m365_providers_can_be_listed(self):
        """m365_audit can be included in providers list."""
        from openlabels.server.config import MonitoringSettings

        s = MonitoringSettings(
            providers=["windows_sacl", "m365_audit", "graph_webhook"],
        )
        assert "m365_audit" in s.providers
        assert "graph_webhook" in s.providers


# =====================================================================
# Integration: M365 provider with EventHarvester
# =====================================================================


class TestM365ProviderWithHarvester:
    """Test that M365AuditProvider works with EventHarvester."""

    @pytest.mark.asyncio
    async def test_harvester_can_use_m365_provider(self):
        """EventHarvester can run a cycle with M365AuditProvider."""
        from openlabels.monitoring.harvester import EventHarvester

        provider = M365AuditProvider("tenant", "client", "secret")
        harvester = EventHarvester([provider])

        # Mock the collect method to return known events
        t = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_events = [
            RawAccessEvent(
                file_path="https://contoso.sharepoint.com/doc.xlsx",
                event_time=t,
                action="read",
                event_source="m365_audit",
                user_name="user@contoso.com",
            ),
        ]

        mock_mf = MagicMock()
        mock_mf.id = "mf-1"
        mock_mf.tenant_id = "t-1"
        mock_mf.file_path = "https://contoso.sharepoint.com/doc.xlsx"
        mock_mf.access_count = 0
        mock_mf.last_event_at = None

        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()

        with (
            patch.object(provider, "collect", return_value=mock_events),
            patch.object(
                EventHarvester,
                "_resolve_monitored_files",
                return_value={"https://contoso.sharepoint.com/doc.xlsx": mock_mf},
            ),
        ):
            count = await harvester.harvest_once(session)

        assert count == 1
        assert harvester._checkpoints["m365_audit"] == t
