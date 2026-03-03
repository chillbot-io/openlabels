"""
Resource enumeration API — connect to a source and list available resources.

After a user provides credentials, this endpoint connects to the target system
and returns the available resources (shares, exports, sites, drives, buckets,
containers) so the user can choose which to monitor.

Each source type has its own enumeration logic:
- SMB:  list network shares via SMB protocol (or local mounts)
- NFS:  list NFS exports (or local /etc/exports)
- SharePoint: list sites and document libraries via Microsoft Graph
- OneDrive: list user drives via Microsoft Graph
- S3:  list buckets via AWS SDK
- GCS: list buckets via Google Cloud SDK
- Azure Blob: list containers via Azure SDK
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import CurrentUser, require_admin
from openlabels.server.db import get_session
from openlabels.server.routes.credentials import (
    SESSION_COOKIE_NAME,
    VALID_SOURCE_TYPES,
    get_decrypted_credentials,
)
from openlabels.server.session import SessionStore
from openlabels.server.utils import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter()
limiter = Limiter(key_func=get_client_ip)

# Hostname: allow alphanumeric, hyphens, dots, IPv4, bracketed IPv6 — no slashes/traversal
_HOST_RE = re.compile(r"^[a-zA-Z0-9\-\.:\[\]]+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\\@\-]+$")


def _validate_host(host: str) -> str:
    """Sanitize and validate a hostname / IP address."""
    host = host.strip()
    if not host:
        raise HTTPException(status_code=400, detail="Host is required")
    if len(host) > 253:
        raise HTTPException(status_code=400, detail="Host is too long (max 253 chars)")
    if not _HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="Host contains invalid characters")
    if ".." in host:
        raise HTTPException(status_code=400, detail="Host contains invalid traversal sequence")
    return host


def _validate_uuid(value: str, label: str) -> str:
    """Validate that a string looks like a UUID."""
    value = value.strip()
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"{label} must be a valid UUID")
    return value


def _safe_json(resp: Any) -> dict:
    """Safely parse JSON from an httpx response, returning {} on failure."""
    try:
        return resp.json()
    except Exception:
        return {}


class EnumerateRequest(BaseModel):
    """Request to enumerate available resources on a source."""
    source_type: str = Field(..., description="Source type to enumerate")
    credentials: dict[str, Any] | None = Field(
        None,
        description="Inline credentials (used if not previously saved). "
        "If omitted, uses saved session credentials.",
    )
    search: str | None = Field(
        None,
        description="Search query to filter resources (server-side for SharePoint/OneDrive).",
    )
    page: int = Field(1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(50, ge=1, le=500, description="Results per page")
    use_m365_session: bool = Field(
        False,
        description="Use M365 tenant credentials from the active session "
        "instead of inline/stored credentials.",
    )


class EnumeratedResource(BaseModel):
    """A single enumerated resource (share, site, bucket, etc.)."""
    id: str = Field(..., description="Unique identifier for this resource")
    name: str = Field(..., description="Display name")
    path: str = Field(..., description="Full path or URI")
    resource_type: str = Field(..., description="Type of resource (share, export, site, bucket, etc.)")
    description: str | None = Field(None, description="Optional description or metadata")
    size: str | None = Field(None, description="Size information if available")


class EnumerateResponse(BaseModel):
    """Response with enumerated resources."""
    source_type: str
    resources: list[EnumeratedResource]
    total: int
    has_more: bool = False
    error: str | None = None


async def _get_credentials(
    request: Request,
    db: AsyncSession,
    user: CurrentUser,
    source_type: str,
    inline_credentials: dict[str, Any] | None,
) -> dict[str, Any]:
    """Resolve credentials: use inline if provided, otherwise load from session."""
    if inline_credentials:
        return inline_credentials

    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(status_code=401, detail="No active session")

    store = SessionStore(db)
    session_data = await store.get(session_id)
    if session_data is None:
        raise HTTPException(status_code=401, detail="Session expired")

    creds = get_decrypted_credentials(session_data, str(user.id), source_type)
    if creds is None:
        raise HTTPException(
            status_code=400,
            detail=f"No credentials found for {source_type}. Please provide credentials.",
        )
    return creds


# ── SMB enumeration ──────────────────────────────────────────────────

async def _enumerate_smb(creds: dict[str, Any]) -> list[EnumeratedResource]:
    """Enumerate SMB shares on a host."""
    host = _validate_host(creds.get("host", ""))
    username = creds.get("username", "").strip()
    password = creds.get("password", "")

    # Validate username against strict allowlist to prevent injection
    if username and not _USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username contains invalid characters",
        )

    # Check if this is localhost — enumerate local shares
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return await _enumerate_local_shares()

    resources: list[EnumeratedResource] = []

    # Try smbclient -L to list shares
    try:
        # SECURITY: Pass credentials via environment variable to avoid
        # leaking them in /proc/cmdline or ps output, and to prevent
        # shell metacharacter injection via the password value.
        env = None
        if username:
            cmd = ["smbclient", "-L", f"//{host}", "-U", username]
            if password:
                import os as _os
                env = {**_os.environ, "PASSWD": password}
            else:
                cmd.append("-N")
        else:
            cmd = ["smbclient", "-L", f"//{host}", "-N"]

        result = await asyncio.to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )

        # Parse smbclient output
        in_share_section = False
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Sharename") or line.startswith("---------"):
                in_share_section = True
                continue
            if in_share_section and line:
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1]
                    description = " ".join(parts[2:]) if len(parts) > 2 else None

                    # Skip IPC$ and printer shares
                    if share_type.upper() in ("IPC", "PRINTER"):
                        continue

                    # Use a mount-convention path that the filesystem adapter
                    # can work with.  The UNC path goes in description.
                    mount_path = f"/mnt/smb/{host}/{share_name}"
                    resources.append(EnumeratedResource(
                        id=f"smb://{host}/{share_name}",
                        name=share_name,
                        path=mount_path,
                        resource_type="share",
                        description=f"\\\\{host}\\{share_name}"
                        + (f" — {description}" if description else ""),
                    ))
            elif in_share_section and not line:
                break  # End of share section
    except FileNotFoundError:
        # smbclient not installed — return helpful message
        logger.warning("smbclient not found, using fallback SMB enumeration")
        resources.append(EnumeratedResource(
            id=f"smb://{host}/manual",
            name="(Enter share name manually)",
            path=f"/mnt/smb/{host}",
            resource_type="share",
            description="smbclient not installed — enter share paths manually",
        ))
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail=f"Connection to {host} timed out")
    except Exception as e:
        logger.exception("SMB enumeration failed for %s", host)
        raise HTTPException(status_code=502, detail="SMB enumeration failed: internal error")

    return resources


async def _enumerate_local_shares() -> list[EnumeratedResource]:
    """Enumerate local SMB shares via net share or smb.conf."""
    resources: list[EnumeratedResource] = []

    # Try parsing smb.conf
    smb_conf = "/etc/samba/smb.conf"
    if os.path.isfile(smb_conf):
        try:
            with open(smb_conf) as f:
                current_share = None
                current_path = None
                current_comment = None
                for line in f:
                    line = line.strip()
                    if line.startswith("[") and line.endswith("]"):
                        # Save previous share
                        if current_share and current_share not in ("global", "printers", "print$"):
                            resources.append(EnumeratedResource(
                                id=f"smb://localhost/{current_share}",
                                name=current_share,
                                path=current_path or f"/srv/samba/{current_share}",
                                resource_type="share",
                                description=current_comment,
                            ))
                        current_share = line[1:-1]
                        current_path = None
                        current_comment = None
                    elif "=" in line:
                        key, _, val = line.partition("=")
                        key = key.strip().lower()
                        val = val.strip()
                        if key == "path":
                            current_path = val
                        elif key == "comment":
                            current_comment = val

                # Don't forget the last share
                if current_share and current_share not in ("global", "printers", "print$"):
                    resources.append(EnumeratedResource(
                        id=f"smb://localhost/{current_share}",
                        name=current_share,
                        path=current_path or f"/srv/samba/{current_share}",
                        resource_type="share",
                        description=current_comment,
                    ))
        except PermissionError:
            logger.warning("Cannot read %s — insufficient permissions", smb_conf)

    # Also list common mount points
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["mount", "-t", "cifs"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "on":
                source = parts[0]
                mount_point = parts[2]
                resources.append(EnumeratedResource(
                    id=f"local:{mount_point}",
                    name=os.path.basename(mount_point) or mount_point,
                    path=mount_point,
                    resource_type="mount",
                    description=f"Mounted from {source}",
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # If nothing found, add common paths
    if not resources:
        for d in ("/mnt", "/srv/samba", "/home"):
            if os.path.isdir(d):
                try:
                    entries = os.listdir(d)
                    for entry in sorted(entries):
                        full_path = os.path.join(d, entry)
                        if os.path.isdir(full_path):
                            resources.append(EnumeratedResource(
                                id=f"local:{full_path}",
                                name=entry,
                                path=full_path,
                                resource_type="directory",
                                description=f"Local directory in {d}",
                            ))
                except PermissionError:
                    continue

    return resources


# ── NFS enumeration ──────────────────────────────────────────────────

async def _enumerate_nfs(creds: dict[str, Any]) -> list[EnumeratedResource]:
    """Enumerate NFS exports on a host."""
    host = _validate_host(creds.get("host", ""))

    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return await _enumerate_local_nfs()

    resources: list[EnumeratedResource] = []

    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["showmount", "-e", host],
            capture_output=True,
            text=True,
            timeout=15,
        )

        for line in result.stdout.splitlines()[1:]:  # Skip header
            line = line.strip()
            if line:
                parts = line.split()
                if parts:
                    export_path = parts[0]
                    allowed = " ".join(parts[1:]) if len(parts) > 1 else "*"
                    # Use a mount-convention path; put host:path in description
                    dir_name = os.path.basename(export_path) or export_path.strip("/")
                    mount_path = f"/mnt/nfs/{host}/{dir_name}"
                    resources.append(EnumeratedResource(
                        id=f"nfs://{host}{export_path}",
                        name=dir_name,
                        path=mount_path,
                        resource_type="export",
                        description=f"{host}:{export_path} (Allowed: {allowed})",
                    ))
    except FileNotFoundError:
        logger.warning("showmount not found, trying /etc/exports")
        resources.append(EnumeratedResource(
            id=f"nfs://{host}/manual",
            name="(Enter export path manually)",
            path=f"/mnt/nfs/{host}",
            resource_type="export",
            description="showmount not installed — enter export paths manually",
        ))
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail=f"Connection to {host} timed out")
    except Exception as e:
        logger.exception("NFS enumeration failed for %s", host)
        raise HTTPException(status_code=502, detail="NFS enumeration failed: internal error")

    return resources


async def _enumerate_local_nfs() -> list[EnumeratedResource]:
    """Enumerate local NFS exports from /etc/exports."""
    resources: list[EnumeratedResource] = []

    exports_file = "/etc/exports"
    if os.path.isfile(exports_file):
        try:
            with open(exports_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if parts:
                            export_path = parts[0]
                            options = " ".join(parts[1:])
                            resources.append(EnumeratedResource(
                                id=f"nfs://localhost{export_path}",
                                name=os.path.basename(export_path) or export_path,
                                path=export_path,
                                resource_type="export",
                                description=f"Options: {options}" if options else None,
                            ))
        except PermissionError:
            logger.warning("Cannot read /etc/exports")

    # Also list NFS mounts
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["mount", "-t", "nfs,nfs4"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "on":
                source = parts[0]
                mount_point = parts[2]
                resources.append(EnumeratedResource(
                    id=f"local:{mount_point}",
                    name=os.path.basename(mount_point) or mount_point,
                    path=mount_point,
                    resource_type="mount",
                    description=f"Mounted from {source}",
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return resources


# ── SharePoint enumeration ───────────────────────────────────────────

async def _enumerate_sharepoint(
    creds: dict[str, Any],
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[EnumeratedResource], bool]:
    """Enumerate SharePoint sites via Microsoft Graph API.

    Supports server-side search and pagination for large tenants (15k+ sites).
    Returns (resources, has_more).
    """
    tenant_id = creds.get("tenant_id", "").strip()
    client_id = creds.get("client_id", "").strip()
    client_secret = creds.get("client_secret", "")

    if not all([tenant_id, client_id, client_secret]):
        raise HTTPException(
            status_code=400,
            detail="SharePoint requires tenant_id, client_id, and client_secret",
        )

    _validate_uuid(tenant_id, "Tenant ID")
    _validate_uuid(client_id, "Client ID")

    try:
        import httpx
    except ImportError:
        raise HTTPException(status_code=500, detail="httpx not installed")

    # Get access token
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        token_resp = await client.post(token_url, data=token_data)
        if token_resp.status_code != 200:
            error_detail = _safe_json(token_resp).get("error_description", "Authentication failed")
            raise HTTPException(status_code=401, detail=f"SharePoint auth failed: {error_detail}")

        access_token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}

        # Build search URL — Graph API supports search= parameter on /sites
        search_term = search.strip() if search else "*"
        # Request one extra to detect has_more
        fetch_size = page_size + 1
        skip = (page - 1) * page_size
        url = (
            f"https://graph.microsoft.com/v1.0/sites"
            f"?search={search_term}&$top={fetch_size}&$skip={skip}"
            f"&$select=id,displayName,webUrl,description"
        )

        sites_resp = await client.get(url, headers=headers)
        if sites_resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Failed to enumerate SharePoint sites")

        raw_sites = sites_resp.json().get("value", [])
        has_more = len(raw_sites) > page_size
        sites = raw_sites[:page_size]

        resources: list[EnumeratedResource] = []
        for site in sites:
            site_id = site.get("id", "")
            site_name = site.get("displayName", "Unknown")
            site_url = site.get("webUrl", "")

            resources.append(EnumeratedResource(
                id=site_id,
                name=site_name,
                path=site_url,
                resource_type="site",
                description=site.get("description"),
            ))

        return resources, has_more


# ── OneDrive enumeration ─────────────────────────────────────────────

async def _enumerate_onedrive(
    creds: dict[str, Any],
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[EnumeratedResource], bool]:
    """Enumerate OneDrive user drives via Microsoft Graph API.

    Supports server-side search (by displayName/mail) and pagination.
    Returns (resources, has_more).
    """
    tenant_id = creds.get("tenant_id", "").strip()
    client_id = creds.get("client_id", "").strip()
    client_secret = creds.get("client_secret", "")

    if not all([tenant_id, client_id, client_secret]):
        raise HTTPException(
            status_code=400,
            detail="OneDrive requires tenant_id, client_id, and client_secret",
        )

    _validate_uuid(tenant_id, "Tenant ID")
    _validate_uuid(client_id, "Client ID")

    try:
        import httpx
    except ImportError:
        raise HTTPException(status_code=500, detail="httpx not installed")

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        token_resp = await client.post(token_url, data=token_data)
        if token_resp.status_code != 200:
            error_detail = _safe_json(token_resp).get("error_description", "Authentication failed")
            raise HTTPException(status_code=401, detail=f"OneDrive auth failed: {error_detail}")

        access_token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}

        # Build URL with optional search filter and pagination
        fetch_size = page_size + 1
        skip = (page - 1) * page_size
        base_url = "https://graph.microsoft.com/v1.0/users"
        params = f"$select=id,displayName,mail,userPrincipalName&$top={fetch_size}&$skip={skip}"

        if search and search.strip():
            # Use $filter with startsWith for server-side filtering
            safe_search = search.strip().replace("'", "''")
            params += (
                f"&$filter=startsWith(displayName,'{safe_search}')"
                f" or startsWith(mail,'{safe_search}')"
            )

        users_resp = await client.get(f"{base_url}?{params}", headers=headers)
        if users_resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Failed to enumerate OneDrive users")

        raw_users = users_resp.json().get("value", [])
        has_more = len(raw_users) > page_size
        users = raw_users[:page_size]

        resources: list[EnumeratedResource] = []
        for user in users:
            user_id = user.get("id", "")
            display_name = user.get("displayName", "Unknown")
            email = user.get("mail") or user.get("userPrincipalName", "")

            resources.append(EnumeratedResource(
                id=user_id,
                name=display_name,
                path=email,
                resource_type="drive",
                description=f"OneDrive for {email}",
            ))

        return resources, has_more


# ── S3 enumeration ───────────────────────────────────────────────────

async def _enumerate_s3(creds: dict[str, Any]) -> list[EnumeratedResource]:
    """Enumerate S3 buckets."""
    access_key = creds.get("access_key", "").strip()
    secret_key = creds.get("secret_key", "")
    region = creds.get("region", "us-east-1").strip()
    endpoint_url = creds.get("endpoint_url", "").strip() or None

    # SECURITY: Validate endpoint_url against SSRF (private/internal IPs)
    if endpoint_url:
        from openlabels.adapters.s3 import _validate_endpoint_url
        try:
            _validate_endpoint_url(endpoint_url)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        raise HTTPException(status_code=500, detail="boto3 not installed")

    try:
        kwargs: dict[str, Any] = {"service_name": "s3", "region_name": region}
        if access_key and secret_key:
            kwargs["aws_access_key_id"] = access_key
            kwargs["aws_secret_access_key"] = secret_key
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url

        s3_client = await asyncio.to_thread(boto3.client, **kwargs)
        response = await asyncio.to_thread(s3_client.list_buckets)

        resources: list[EnumeratedResource] = []
        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]
            created = bucket.get("CreationDate")
            resources.append(EnumeratedResource(
                id=bucket_name,
                name=bucket_name,
                path=f"s3://{bucket_name}",
                resource_type="bucket",
                description=f"Created: {created.isoformat()}" if created else None,
            ))
        return resources

    except NoCredentialsError:
        raise HTTPException(status_code=401, detail="Invalid or missing AWS credentials")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        raise HTTPException(status_code=502, detail=f"S3 error: {error_code}")
    except Exception as e:
        logger.exception("S3 enumeration failed")
        raise HTTPException(status_code=502, detail="S3 enumeration failed: internal error")


# ── GCS enumeration ──────────────────────────────────────────────────

async def _enumerate_gcs(creds: dict[str, Any]) -> list[EnumeratedResource]:
    """Enumerate Google Cloud Storage buckets."""
    project = creds.get("project", "").strip()
    credentials_json = creds.get("credentials_json", "").strip()

    try:
        from google.cloud import storage as gcs_storage
        from google.oauth2 import service_account
    except ImportError:
        raise HTTPException(status_code=500, detail="google-cloud-storage not installed")

    try:
        import json as json_module

        if credentials_json:
            cred_info = json_module.loads(credentials_json)
            gcp_creds = service_account.Credentials.from_service_account_info(cred_info)
            client = gcs_storage.Client(project=project or None, credentials=gcp_creds)
        else:
            client = gcs_storage.Client(project=project or None)

        buckets = await asyncio.to_thread(list, client.list_buckets())

        resources: list[EnumeratedResource] = []
        for bucket in buckets:
            resources.append(EnumeratedResource(
                id=bucket.name,
                name=bucket.name,
                path=f"gs://{bucket.name}",
                resource_type="bucket",
                description=f"Location: {bucket.location}" if bucket.location else None,
            ))
        return resources

    except Exception as e:
        logger.exception("GCS enumeration failed")
        raise HTTPException(status_code=502, detail="GCS enumeration failed: internal error")


# ── Azure Blob enumeration ───────────────────────────────────────────

async def _enumerate_azure_blob(creds: dict[str, Any]) -> list[EnumeratedResource]:
    """Enumerate Azure Blob Storage containers."""
    storage_account = creds.get("storage_account", "").strip()
    account_key = creds.get("account_key", "").strip()

    if not storage_account:
        raise HTTPException(status_code=400, detail="Azure storage_account is required")

    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        raise HTTPException(status_code=500, detail="azure-storage-blob not installed")

    try:
        account_url = f"https://{storage_account}.blob.core.windows.net"
        if account_key:
            client = BlobServiceClient(account_url=account_url, credential=account_key)
        else:
            from azure.identity import DefaultAzureCredential
            client = BlobServiceClient(account_url=account_url, credential=DefaultAzureCredential())

        containers = await asyncio.to_thread(list, client.list_containers())

        resources: list[EnumeratedResource] = []
        for container in containers:
            name = container["name"]
            resources.append(EnumeratedResource(
                id=name,
                name=name,
                path=f"{account_url}/{name}",
                resource_type="container",
                description=None,
            ))
        return resources

    except Exception as e:
        logger.exception("Azure Blob enumeration failed")
        raise HTTPException(status_code=502, detail="Azure Blob enumeration failed: internal error")


# ── Dispatch ─────────────────────────────────────────────────────────

_ENUMERATORS = {
    "smb": _enumerate_smb,
    "nfs": _enumerate_nfs,
    "sharepoint": _enumerate_sharepoint,
    "onedrive": _enumerate_onedrive,
    "s3": _enumerate_s3,
    "gcs": _enumerate_gcs,
    "azure_blob": _enumerate_azure_blob,
}

# Enumerators that support search/pagination return (list, has_more)
_PAGINATED_ENUMERATORS = {"sharepoint", "onedrive"}


async def _get_m365_session_credentials(
    request: Request, db: AsyncSession
) -> dict[str, Any]:
    """Build Graph API credentials from the M365 tenant stored in the session.

    Prefers per-tenant app credentials (created during auto app registration)
    if available in the session. Falls back to the bootstrap app's credentials
    from settings.
    """
    from openlabels.server.config import get_settings

    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(status_code=401, detail="No active session")

    store = SessionStore(db)
    session_data = await store.get(session_id)
    if session_data is None:
        raise HTTPException(status_code=401, detail="Session expired")

    # Prefer per-tenant app credentials from auto registration
    app_creds = session_data.get("m365_app_credentials")
    if app_creds and app_creds.get("client_id") and app_creds.get("client_secret"):
        return {
            "tenant_id": app_creds["tenant_id"],
            "client_id": app_creds["client_id"],
            "client_secret": app_creds["client_secret"],
        }

    # Fall back to bootstrap app
    m365_info = session_data.get("m365_tenant")
    if not m365_info or not m365_info.get("tenant_id"):
        raise HTTPException(
            status_code=400,
            detail="No M365 tenant connected. Complete the M365 setup first.",
        )

    settings = get_settings()
    if not settings.m365.client_id or not settings.m365.client_secret.get_secret_value():
        raise HTTPException(
            status_code=500,
            detail="M365 integration is not configured on the server.",
        )

    return {
        "tenant_id": m365_info["tenant_id"],
        "client_id": settings.m365.client_id,
        "client_secret": settings.m365.client_secret.get_secret_value(),
    }


@router.post("", response_model=EnumerateResponse)
@limiter.limit("10/minute")
async def enumerate_resources(
    request: Request,
    body: EnumerateRequest,
    db: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> EnumerateResponse:
    """Connect to a source and enumerate available resources.

    Uses inline credentials if provided, otherwise falls back to
    saved session credentials. For M365 sources, set use_m365_session=true
    to use the tenant connected via admin consent.
    """
    if body.source_type not in VALID_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid source type: {body.source_type}")

    # Resolve credentials
    if body.use_m365_session and body.source_type in ("sharepoint", "onedrive"):
        creds = await _get_m365_session_credentials(request, db)
    else:
        creds = await _get_credentials(request, db, user, body.source_type, body.credentials)

    enumerator = _ENUMERATORS.get(body.source_type)
    if not enumerator:
        raise HTTPException(status_code=400, detail=f"No enumerator for: {body.source_type}")

    # Paginated enumerators get search/page params
    if body.source_type in _PAGINATED_ENUMERATORS:
        resources, has_more = await enumerator(
            creds,
            search=body.search,
            page=body.page,
            page_size=body.page_size,
        )
    else:
        resources = await enumerator(creds)
        has_more = False

    return EnumerateResponse(
        source_type=body.source_type,
        resources=resources,
        total=len(resources),
        has_more=has_more,
    )
