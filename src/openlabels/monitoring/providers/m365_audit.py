"""
M365 Management Activity API audit provider.

Collects file access events from the Office 365 unified audit log
(``Audit.SharePoint`` content type) which covers both SharePoint Online
and OneDrive for Business.

API reference:
    https://learn.microsoft.com/en-us/office/office-365-management-api/

Authentication:
    Uses the same Azure AD app registration as the Graph API client
    (``client_id`` / ``client_secret``), but acquires a token scoped to
    ``https://manage.office.com/.default`` (the Management Activity API
    resource) instead of ``https://graph.microsoft.com/.default``.

    The app registration must have the ``ActivityFeed.Read`` application
    permission from the *Office 365 Management APIs* resource, with
    admin consent granted.

Subscription model:
    1. ``POST /subscriptions/start?contentType=Audit.SharePoint``
       — starts collecting audit content for the tenant.
    2. ``GET /subscriptions/content?contentType=Audit.SharePoint``
       — lists available content blobs (7-day window).
    3. ``GET {contentUri}`` — fetches a blob (JSON array of events).
    4. Content blobs are available for 7 days after creation.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx

# Allowed domains for M365 Management Activity API content blob URIs.
# See: https://learn.microsoft.com/en-us/office/office-365-management-api/
_ALLOWED_CONTENT_DOMAINS = frozenset({
    "manage.office.com",
    "manage-gcc.office.com",
    "manage.office365.us",        # GCC High
    "manage.protection.outlook.com",
})

from .base import RawAccessEvent

logger = logging.getLogger(__name__)

# Management Activity API base URL
_MANAGE_API_BASE = "https://manage.office.com/api/v1.0"
_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_MANAGE_SCOPE = "https://manage.office.com/.default"

EVENT_SOURCE = "m365_audit"
CONTENT_TYPE = "Audit.SharePoint"

# M365 operation → RawAccessEvent action mapping
M365_OPERATION_MAP: dict[str, str] = {
    # File access
    "FileAccessed": "read",
    "FileAccessedExtended": "read",
    "FilePreviewed": "read",
    "FileDownloaded": "read",
    "FileSyncDownloadedFull": "read",
    "FileSyncDownloadedPartial": "read",
    "FileCopied": "read",
    # File modification
    "FileModified": "write",
    "FileModifiedExtended": "write",
    "FileUploaded": "write",
    "FileSyncUploadedFull": "write",
    "FileSyncUploadedPartial": "write",
    "FileCheckedOut": "write",
    "FileCheckedIn": "write",
    "FileRestored": "write",
    # File deletion
    "FileDeleted": "delete",
    "FileDeletedFirstStageRecycleBin": "delete",
    "FileDeletedSecondStageRecycleBin": "delete",
    "FileRecycled": "delete",
    "FileVersionsAllDeleted": "delete",
    # Rename / move
    "FileMoved": "rename",
    "FileRenamed": "rename",
    # Permission changes
    "SharingSet": "permission_change",
    "SharingRevoked": "permission_change",
    "SharingInheritanceBroken": "permission_change",
    "SharingInheritanceReset": "permission_change",
    "AnonymousLinkCreated": "permission_change",
    "AnonymousLinkUpdated": "permission_change",
    "AnonymousLinkRemoved": "permission_change",
    "CompanyLinkCreated": "permission_change",
    "CompanyLinkRemoved": "permission_change",
    "AddedToSecureLink": "permission_change",
    "RemovedFromSecureLink": "permission_change",
}

# Maximum number of content blobs to fetch per cycle (back-pressure).
_MAX_CONTENT_BLOBS_PER_CYCLE = 200

# Token refresh buffer — request a new token 60s before expiry.
_TOKEN_REFRESH_BUFFER_SECONDS = 60


class M365AuditProvider:
    """Collects file-access audit events from the M365 Management Activity API.

    Implements the ``EventProvider`` async protocol.

    Parameters
    ----------
    tenant_id:
        Azure AD tenant ID (GUID).
    client_id:
        App registration client / application ID (GUID).
    client_secret:
        App registration client secret value.
    monitored_site_urls:
        If provided, only events from these SharePoint site URLs are
        returned.  Each entry is matched as a prefix against the event's
        ``SiteUrl`` field.  ``None`` means collect from all sites.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        *,
        monitored_site_urls: list[str] | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret: str = client_secret
        self._monitored_site_urls = monitored_site_urls

        self._base_url = f"{_MANAGE_API_BASE}/{tenant_id}/activity/feed"

        # Token management (separate from Graph API)
        self._access_token: str | None = None
        self._token_expires_at: datetime | None = None
        self._token_lock = asyncio.Lock()

        # HTTP client — created lazily, shared across calls
        self._client: httpx.AsyncClient | None = None

        # Subscription state (re-verified every 6 hours)
        self._subscription_active = False
        self._subscription_verified_at: datetime | None = None
        self._subscription_ttl = timedelta(hours=6)

    @property
    def name(self) -> str:
        return EVENT_SOURCE

    # EventProvider.collect()
    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        """Collect audit events from M365.

        Steps:
        1. Ensure we have an active subscription.
        2. List available content blobs since ``since``.
        3. Fetch each blob and extract ``RawAccessEvent`` instances.
        """
        client = await self._get_client()

        # Ensure subscription is active
        await self._ensure_subscription(client)

        # Build time window for content listing
        end_time = datetime.now(timezone.utc)
        if since is None:
            # First run — look back 24 hours (API supports up to 7 days)
            start_time = end_time - timedelta(hours=24)
        else:
            start_time = since

        # List content blobs
        content_uris = await self._list_content(client, start_time, end_time)

        if not content_uris:
            return []

        # Fetch content blobs (with back-pressure cap)
        if len(content_uris) > _MAX_CONTENT_BLOBS_PER_CYCLE:
            logger.warning(
                "M365 audit: %d content blobs available (cap=%d), truncating",
                len(content_uris),
                _MAX_CONTENT_BLOBS_PER_CYCLE,
            )
            content_uris = content_uris[:_MAX_CONTENT_BLOBS_PER_CYCLE]

        events: list[RawAccessEvent] = []
        for uri in content_uris:
            try:
                blob_events = await self._fetch_content_blob(client, uri)
                events.extend(blob_events)
            except Exception:
                logger.warning(
                    "Failed to fetch content blob: %s", uri, exc_info=True,
                )

        return events

    # Token management
    async def _ensure_token(self) -> str:
        """Ensure we have a valid access token for manage.office.com."""
        async with self._token_lock:
            now = datetime.now(timezone.utc)

            if (
                self._access_token
                and self._token_expires_at
                and self._token_expires_at > now + timedelta(
                    seconds=_TOKEN_REFRESH_BUFFER_SECONDS,
                )
            ):
                return self._access_token

            token_url = _TOKEN_URL.format(tenant_id=self._tenant_id)
            data = {
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": _MANAGE_SCOPE,
                "grant_type": "client_credentials",
            }

            async with httpx.AsyncClient(timeout=30.0) as temp_client:
                response = await temp_client.post(token_url, data=data)
                response.raise_for_status()
                token_data = response.json()

            self._access_token = token_data["access_token"]
            expires_in = int(token_data.get("expires_in", 3600))
            self._token_expires_at = now + timedelta(seconds=expires_in)

            logger.debug(
                "M365 Management API token acquired (expires in %ds)",
                expires_in,
            )
            return self._access_token

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the shared HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=10.0),
            )
        return self._client

    async def _authorized_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """Make an authorized request to the Management Activity API."""
        token = await self._ensure_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        response = await client.request(method, url, headers=headers, **kwargs)
        return response

    # Subscription management
    async def _ensure_subscription(self, client: httpx.AsyncClient) -> None:
        """Ensure the Audit.SharePoint subscription is active.

        Re-verifies the subscription status periodically (every 6 hours)
        in case the subscription was disabled on the M365 side.
        """
        now = datetime.now(timezone.utc)
        if (
            self._subscription_active
            and self._subscription_verified_at
            and (now - self._subscription_verified_at) < self._subscription_ttl
        ):
            return

        # Check current subscriptions
        url = f"{self._base_url}/subscriptions/list"
        response = await self._authorized_request(client, "GET", url)
        response.raise_for_status()

        subscriptions = response.json()
        for sub in subscriptions:
            if (
                sub.get("contentType") == CONTENT_TYPE
                and sub.get("status") == "enabled"
            ):
                self._subscription_active = True
                self._subscription_verified_at = now
                logger.debug("M365 Audit.SharePoint subscription is active")
                return

        # Start subscription
        start_url = (
            f"{self._base_url}/subscriptions/start"
            f"?contentType={CONTENT_TYPE}"
        )
        response = await self._authorized_request(client, "POST", start_url)

        if response.status_code in (200, 201):
            self._subscription_active = True
            self._subscription_verified_at = now
            logger.info("M365 Audit.SharePoint subscription started")
        else:
            logger.error(
                "Failed to start M365 audit subscription: %d %s",
                response.status_code,
                response.text,
            )
            response.raise_for_status()

    # Content listing and blob fetching (H.4: pagination)
    async def _list_content(
        self,
        client: httpx.AsyncClient,
        start_time: datetime,
        end_time: datetime,
    ) -> list[str]:
        """List available content blob URIs in the time window.

        The Management Activity API paginates via ``NextPageUri`` in
        the response headers.  We follow pages up to a safety limit
        to prevent unbounded loops from cyclical or excessive responses.
        """
        max_pages = 500  # Safety limit
        uris: list[str] = []

        # Format times as required by the API
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%S")

        url: str | None = (
            f"{self._base_url}/subscriptions/content"
            f"?contentType={CONTENT_TYPE}"
            f"&startTime={start_str}"
            f"&endTime={end_str}"
        )

        pages_fetched = 0
        while url:
            if pages_fetched >= max_pages:
                logger.warning(
                    "M365 content listing: hit page limit (%d), stopping",
                    max_pages,
                )
                break

            response = await self._authorized_request(client, "GET", url)
            pages_fetched += 1

            if response.status_code == 200:
                blobs = response.json()
                for blob in blobs:
                    content_uri = blob.get("contentUri")
                    if content_uri:
                        uris.append(content_uri)

                # Follow pagination
                url = response.headers.get("NextPageUri")
            else:
                logger.warning(
                    "M365 content listing failed: %d %s",
                    response.status_code,
                    response.text,
                )
                break

        return uris

    async def _fetch_content_blob(
        self,
        client: httpx.AsyncClient,
        content_uri: str,
    ) -> list[RawAccessEvent]:
        """Fetch a single content blob and parse audit events."""
        # SECURITY: Validate domain to prevent SSRF via tampered API responses
        parsed = urlparse(content_uri)
        if parsed.hostname and parsed.hostname not in _ALLOWED_CONTENT_DOMAINS:
            logger.warning(
                "Blocked content blob fetch to untrusted domain: %s",
                parsed.hostname,
            )
            return []
        response = await self._authorized_request(
            client, "GET", content_uri,
        )
        response.raise_for_status()
        records = response.json()

        events: list[RawAccessEvent] = []
        for record in records:
            event = _parse_audit_record(record, self._monitored_site_urls)
            if event is not None:
                events.append(event)

        return events

    # Cleanup
    async def close(self) -> None:
        """Close the HTTP client and clear credentials."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
        self._client_secret = ""
        self._access_token = None
        self._token_expires_at = None


# Record parsing
def _parse_audit_record(
    record: dict,
    monitored_site_urls: list[str] | None = None,
) -> RawAccessEvent | None:
    """Parse a single M365 audit record into a RawAccessEvent.

    Returns ``None`` if the record should be skipped (unmapped operation,
    non-file item, or filtered site).
    """
    operation = record.get("Operation", "")
    action = M365_OPERATION_MAP.get(operation)
    if action is None:
        return None

    # Only interested in file events (not Folder or Web)
    item_type = record.get("ItemType", "")
    if item_type and item_type != "File":
        return None

    # Site URL filtering
    if monitored_site_urls:
        site_url = record.get("SiteUrl", "")
        if not any(site_url.startswith(prefix) for prefix in monitored_site_urls):
            return None

    # Parse event time
    event_time_str = record.get("CreationTime", "")
    if event_time_str:
        try:
            event_time = datetime.fromisoformat(
                event_time_str.replace("Z", "+00:00"),
            )
        except (ValueError, TypeError):
            event_time = datetime.now(timezone.utc)
    else:
        event_time = datetime.now(timezone.utc)

    # Build file path from ObjectId or SourceRelativeUrl
    # ObjectId is typically the full URL; SourceRelativeUrl is the site-relative path
    file_path = record.get("ObjectId", "")
    if not file_path:
        site_url = record.get("SiteUrl", "")
        relative_url = record.get("SourceRelativeUrl", "")
        source_name = record.get("SourceFileName", "")
        if site_url and relative_url:
            file_path = f"{site_url}/{relative_url}/{source_name}"
        elif source_name:
            file_path = source_name

    if not file_path:
        return None

    return RawAccessEvent(
        file_path=file_path,
        event_time=event_time,
        action=action,
        event_source=EVENT_SOURCE,
        user_name=record.get("UserId"),
        user_sid=record.get("UserKey"),
        raw=record,
    )
