"""
Microsoft 365 admin consent and automatic app registration.

Implements a zero-portal-work onboarding flow:

1. Admin clicks "Connect to Microsoft 365" in the setup wizard
2. Backend redirects to Microsoft's /adminconsent endpoint
3. Global Admin signs in and grants permissions to our bootstrap app
4. Microsoft redirects back to our callback with tenant ID
5. Backend verifies Graph API access
6. Backend creates a dedicated app registration in the customer's tenant
   with only the permissions OpenLabels needs (Sites.Read.All, etc.)
7. The new app's credentials are encrypted and stored for scheduled scans
8. Wizard shows "Connected to <tenant>" with a green checkmark

The bootstrap app (configured via OPENLABELS_M365__CLIENT_ID) needs
Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All so it
can provision per-tenant apps. If auto-registration fails (e.g. the
bootstrap app doesn't have those permissions), we fall back to using
the bootstrap app directly — the admin consent already granted it
access to the tenant's data.
"""

from __future__ import annotations

import hmac
import html
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import CurrentUser, require_admin
from openlabels.server.config import get_settings
from openlabels.server.db import get_session
from openlabels.server.models import SavedCredential
from openlabels.server.routes import audit_log
from openlabels.server.routes.credentials import _encrypt
from openlabels.server.session import SessionStore

logger = logging.getLogger(__name__)

router = APIRouter()

SESSION_COOKIE_NAME = "openlabels_session"

_CONSENT_STATE_KEY = "m365_consent_state"
_M365_TENANT_KEY = "m365_tenant"

# Microsoft Graph well-known app ID
_GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000"

# Graph API application permission IDs (appRole type)
_GRAPH_PERMISSIONS = {
    "Sites.Read.All": "332a536c-c7ef-4017-ab91-336970924f0d",
    "Files.Read.All": "01d4f6ba-2834-4990-a0d4-62d0b69f2b4e",
    "User.Read.All": "df021288-bdef-4463-88db-98f22de89214",
}

# Display name used for app registrations created in customer tenants
_APP_DISPLAY_NAME = "OpenLabels Connector"


class M365StatusResponse(BaseModel):
    """Current M365 connection status."""
    connected: bool
    tenant_id: str | None = None
    tenant_name: str | None = None
    has_dedicated_app: bool = False


class M365ConsentStartResponse(BaseModel):
    """Response with the admin consent URL."""
    consent_url: str


# ── Helpers ──────────────────────────────────────────────────────────

def _get_m365_config() -> tuple[str, str]:
    """Get the bootstrap M365 app's client_id and client_secret."""
    settings = get_settings()
    client_id = settings.m365.client_id
    client_secret = settings.m365.client_secret.get_secret_value()

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="M365 integration is not configured. Set OPENLABELS_M365__CLIENT_ID and OPENLABELS_M365__CLIENT_SECRET.",
        )
    return client_id, client_secret


async def _get_session_data(
    request: Request, db: AsyncSession
) -> tuple[str, dict]:
    """Get session ID and data from the request cookie."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(status_code=401, detail="No active session")
    store = SessionStore(db)
    data = await store.get(session_id)
    if data is None:
        raise HTTPException(status_code=401, detail="Session expired")
    return session_id, data


async def _save_session_data(
    db: AsyncSession, session_id: str, data: dict
) -> None:
    """Save updated session data."""
    store = SessionStore(db)
    await store.set(session_id, data, ttl=60 * 60 * 24 * 7)


async def _get_access_token(tenant_id: str) -> str | None:
    """Acquire an access token for the bootstrap app against a tenant."""
    client_id, client_secret = _get_m365_config()
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            })
            if resp.status_code != 200:
                logger.warning("Token request failed for tenant %s: %s", tenant_id, resp.text[:200])
                return None
            return resp.json()["access_token"]
    except httpx.HTTPError as e:
        logger.warning("Token request error: %s", e)
        return None


async def _verify_graph_access(tenant_id: str) -> dict[str, Any] | None:
    """Verify Graph API access. Returns organization info on success."""
    access_token = await _get_access_token(tenant_id)
    if not access_token:
        return None

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            org_resp = await client.get(
                "https://graph.microsoft.com/v1.0/organization",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if org_resp.status_code != 200:
                return {"id": tenant_id, "displayName": tenant_id}

            orgs = org_resp.json().get("value", [])
            return orgs[0] if orgs else {"id": tenant_id, "displayName": tenant_id}
    except httpx.HTTPError as e:
        logger.warning("Graph API verification failed: %s", e)
        return None


# ── Auto app registration ───────────────────────────────────────────

async def _create_tenant_app(
    tenant_id: str,
    access_token: str,
) -> dict[str, str] | None:
    """Create a dedicated app registration in the customer's tenant.

    Steps:
    1. Check if an app named "OpenLabels Connector" already exists
    2. If not, create the app registration with required permissions
    3. Generate a client secret
    4. Create a service principal
    5. Grant admin consent to each permission

    Returns dict with {client_id, client_secret, object_id} on success,
    None if the bootstrap app lacks Application.ReadWrite.All.
    """
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # 1. Check if app already exists
            search_resp = await client.get(
                "https://graph.microsoft.com/v1.0/applications",
                headers=headers,
                params={"$filter": f"displayName eq '{_APP_DISPLAY_NAME}'", "$top": "1"},
            )
            if search_resp.status_code == 403:
                logger.info("Bootstrap app lacks Application.ReadWrite.All — skipping auto-registration")
                return None

            if search_resp.status_code == 200:
                existing = search_resp.json().get("value", [])
                if existing:
                    app = existing[0]
                    logger.info("Found existing app registration %s in tenant %s", app["appId"], tenant_id)
                    # Rotate the secret for the existing app
                    secret_result = await _add_client_secret(client, headers, app["id"])
                    if not secret_result:
                        return None
                    return {
                        "client_id": app["appId"],
                        "client_secret": secret_result,
                        "object_id": app["id"],
                    }

            # 2. Create the app registration
            app_body = {
                "displayName": _APP_DISPLAY_NAME,
                "signInAudience": "AzureADMyOrg",
                "requiredResourceAccess": [{
                    "resourceAppId": _GRAPH_RESOURCE_APP_ID,
                    "resourceAccess": [
                        {"id": perm_id, "type": "Role"}
                        for perm_id in _GRAPH_PERMISSIONS.values()
                    ],
                }],
            }

            create_resp = await client.post(
                "https://graph.microsoft.com/v1.0/applications",
                headers={**headers, "Content-Type": "application/json"},
                json=app_body,
            )
            if create_resp.status_code not in (200, 201):
                logger.warning(
                    "App registration creation failed (%d): %s",
                    create_resp.status_code, create_resp.text[:300],
                )
                return None

            app = create_resp.json()
            app_object_id = app["id"]
            app_client_id = app["appId"]
            logger.info("Created app registration %s (object %s) in tenant %s", app_client_id, app_object_id, tenant_id)

            # 3. Generate a client secret
            secret_value = await _add_client_secret(client, headers, app_object_id)
            if not secret_value:
                return None

            # 4. Create service principal
            sp_resp = await client.post(
                "https://graph.microsoft.com/v1.0/servicePrincipals",
                headers={**headers, "Content-Type": "application/json"},
                json={"appId": app_client_id},
            )
            if sp_resp.status_code not in (200, 201):
                logger.warning("Service principal creation failed: %s", sp_resp.text[:200])
                return {"client_id": app_client_id, "client_secret": secret_value, "object_id": app_object_id}

            sp = sp_resp.json()
            sp_id = sp["id"]

            # 5. Find the Graph service principal in this tenant (to get its ID for role assignments)
            graph_sp_resp = await client.get(
                "https://graph.microsoft.com/v1.0/servicePrincipals",
                headers=headers,
                params={"$filter": f"appId eq '{_GRAPH_RESOURCE_APP_ID}'", "$top": "1"},
            )
            if graph_sp_resp.status_code != 200:
                logger.warning("Could not find Graph service principal")
                return {"client_id": app_client_id, "client_secret": secret_value, "object_id": app_object_id}

            graph_sps = graph_sp_resp.json().get("value", [])
            if not graph_sps:
                return {"client_id": app_client_id, "client_secret": secret_value, "object_id": app_object_id}

            graph_sp_id = graph_sps[0]["id"]

            # 6. Grant admin consent — assign each app role
            for perm_name, perm_id in _GRAPH_PERMISSIONS.items():
                grant_resp = await client.post(
                    f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignments",
                    headers={**headers, "Content-Type": "application/json"},
                    json={
                        "principalId": sp_id,
                        "resourceId": graph_sp_id,
                        "appRoleId": perm_id,
                    },
                )
                if grant_resp.status_code in (200, 201):
                    logger.info("Granted %s to app %s", perm_name, app_client_id)
                else:
                    logger.warning("Failed to grant %s: %s", perm_name, grant_resp.text[:200])

            return {
                "client_id": app_client_id,
                "client_secret": secret_value,
                "object_id": app_object_id,
            }

    except httpx.HTTPError as e:
        logger.warning("Auto app registration failed: %s", e)
        return None


async def _add_client_secret(
    client: httpx.AsyncClient,
    headers: dict,
    app_object_id: str,
) -> str | None:
    """Add a client secret to an app registration. Returns the secret value."""
    end_date = (datetime.now(timezone.utc) + timedelta(days=730)).isoformat()
    secret_resp = await client.post(
        f"https://graph.microsoft.com/v1.0/applications/{app_object_id}/addPassword",
        headers={**headers, "Content-Type": "application/json"},
        json={
            "passwordCredential": {
                "displayName": "OpenLabels (auto-generated)",
                "endDateTime": end_date,
            }
        },
    )
    if secret_resp.status_code not in (200, 201):
        logger.warning("Client secret creation failed: %s", secret_resp.text[:200])
        return None

    return secret_resp.json().get("secretText")


async def _store_tenant_app_credentials(
    db: AsyncSession,
    tenant_id_uuid,
    m365_tenant_id: str,
    app_creds: dict[str, str],
    user_id,
) -> None:
    """Persist the per-tenant app's credentials in SavedCredential."""
    encrypted = _encrypt({
        "tenant_id": m365_tenant_id,
        "client_id": app_creds["client_id"],
        "client_secret": app_creds["client_secret"],
    })

    # Upsert by tenant + source_type + name
    name = f"M365 — {m365_tenant_id}"
    existing = await db.execute(
        select(SavedCredential).where(
            SavedCredential.tenant_id == tenant_id_uuid,
            SavedCredential.source_type == "m365",
            SavedCredential.name == name,
        )
    )
    row = existing.scalar_one_or_none()

    if row:
        row.encrypted_data = encrypted
        row.fields_stored = ["tenant_id", "client_id", "client_secret"]
    else:
        row = SavedCredential(
            tenant_id=tenant_id_uuid,
            source_type="m365",
            name=name,
            encrypted_data=encrypted,
            fields_stored=["tenant_id", "client_id", "client_secret"],
            created_by=user_id,
        )
        db.add(row)

    await db.flush()


# ── Routes ───────────────────────────────────────────────────────────

@router.get("/status", response_model=M365StatusResponse)
async def m365_status(
    request: Request,
    db: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_admin),
) -> M365StatusResponse:
    """Check current M365 connection status."""
    session_id, session_data = await _get_session_data(request, db)
    tenant_info = session_data.get(_M365_TENANT_KEY)

    if not tenant_info:
        return M365StatusResponse(connected=False)

    return M365StatusResponse(
        connected=True,
        tenant_id=tenant_info.get("tenant_id"),
        tenant_name=tenant_info.get("tenant_name"),
        has_dedicated_app=tenant_info.get("has_dedicated_app", False),
    )


@router.post("/consent/start", response_model=M365ConsentStartResponse)
async def start_consent(
    request: Request,
    db: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_admin),
) -> M365ConsentStartResponse:
    """Generate the admin consent URL and return it.

    The frontend opens this URL in a popup window. The Global Admin
    signs in and grants permissions. Microsoft redirects the popup
    back to our callback endpoint.
    """
    client_id, _secret = _get_m365_config()

    state = secrets.token_urlsafe(32)
    callback_url = str(request.url_for("m365_consent_callback"))

    session_id, session_data = await _get_session_data(request, db)
    session_data[_CONSENT_STATE_KEY] = state
    await _save_session_data(db, session_id, session_data)

    params = urlencode({
        "client_id": client_id,
        "redirect_uri": callback_url,
        "state": state,
        "scope": "https://graph.microsoft.com/.default",
    })
    consent_url = f"https://login.microsoftonline.com/common/adminconsent?{params}"

    return M365ConsentStartResponse(consent_url=consent_url)


@router.get("/consent/callback")
async def m365_consent_callback(
    request: Request,
    admin_consent: str | None = None,
    tenant: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_admin),
) -> HTMLResponse:
    """Handle the redirect from Microsoft's admin consent endpoint.

    After verifying Graph access, attempts to create a dedicated app
    registration in the customer's tenant. Falls back to the bootstrap
    app if auto-registration is not possible.
    """
    if error:
        logger.warning("M365 consent error: %s — %s", error, error_description)
        return _popup_response(success=False, error=error_description or error)

    if not tenant or not state:
        return _popup_response(success=False, error="Missing tenant or state parameter")

    if admin_consent != "True":
        return _popup_response(success=False, error="Admin consent was not granted")

    # Validate state nonce
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return _popup_response(success=False, error="Session expired")

    store = SessionStore(db)
    session_data = await store.get(session_id)
    if not session_data:
        return _popup_response(success=False, error="Session expired")

    expected_state = session_data.get(_CONSENT_STATE_KEY)
    # Use hmac.compare_digest for constant-time comparison to prevent
    # timing side-channel attacks on the consent state nonce (M8).
    if not expected_state or not hmac.compare_digest(expected_state, state):
        logger.warning("M365 consent state mismatch")
        return _popup_response(success=False, error="Invalid state")

    session_data.pop(_CONSENT_STATE_KEY, None)

    # Verify Graph API access with the bootstrap app
    org_info = await _verify_graph_access(tenant)
    if not org_info:
        return _popup_response(
            success=False,
            error="Consent was granted but Graph API access verification failed. "
                  "Permissions may still be propagating — try again in a few minutes.",
        )

    tenant_name = org_info.get("displayName", tenant)
    has_dedicated_app = False

    # Attempt auto app registration
    access_token = await _get_access_token(tenant)
    if access_token:
        app_creds = await _create_tenant_app(tenant, access_token)
        if app_creds:
            has_dedicated_app = True
            logger.info(
                "Auto-registered app %s in tenant %s",
                app_creds["client_id"], tenant,
            )

            # Store the per-tenant app credentials
            # Extract tenant_id (UUID) and user_id from session data
            db_tenant_id = session_data.get("tenant_id")
            db_user_id = session_data.get("user_id")
            if db_tenant_id and db_user_id:
                from uuid import UUID
                try:
                    await _store_tenant_app_credentials(
                        db,
                        tenant_id_uuid=UUID(db_tenant_id),
                        m365_tenant_id=tenant,
                        app_creds=app_creds,
                        user_id=UUID(db_user_id),
                    )
                except Exception:
                    logger.exception("Failed to store per-tenant app credentials")

            # Store the per-tenant credentials in session too so
            # the enumerate route can use them immediately
            session_data["m365_app_credentials"] = {
                "tenant_id": tenant,
                "client_id": app_creds["client_id"],
                "client_secret": app_creds["client_secret"],
            }

    # Store connection info
    session_data[_M365_TENANT_KEY] = {
        "tenant_id": tenant,
        "tenant_name": tenant_name,
        "has_dedicated_app": has_dedicated_app,
    }
    await _save_session_data(db, session_id, session_data)

    logger.info("M365 consent granted for tenant %s (%s), dedicated_app=%s", tenant, tenant_name, has_dedicated_app)

    audit_log(
        db, tenant_id=None, user_id=None,
        action="settings_updated", resource_type="m365",
        details={
            "m365_tenant_id": tenant,
            "tenant_name": tenant_name,
            "has_dedicated_app": has_dedicated_app,
        },
    )

    return _popup_response(
        success=True,
        tenant_id=tenant,
        tenant_name=tenant_name,
    )


@router.post("/disconnect")
async def disconnect_m365(
    request: Request,
    db: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_admin),
) -> dict:
    """Remove the M365 tenant connection."""
    session_id, session_data = await _get_session_data(request, db)
    session_data.pop(_M365_TENANT_KEY, None)
    session_data.pop(_CONSENT_STATE_KEY, None)
    session_data.pop("m365_app_credentials", None)
    await _save_session_data(db, session_id, session_data)
    return {"status": "ok"}


# ── Popup response helper ────────────────────────────────────────────

def _popup_response(
    success: bool,
    tenant_id: str | None = None,
    tenant_name: str | None = None,
    error: str | None = None,
) -> HTMLResponse:
    """Return an HTML page that posts a message to the parent window and closes."""
    import json

    # SECURITY: Escape all user-supplied values to prevent XSS injection.
    # tenant_name comes from Microsoft Graph (displayName) and error may
    # contain user-supplied query parameters — both must be escaped before
    # being embedded in the HTML response.
    safe_tenant_id = html.escape(tenant_id or "", quote=True)
    safe_tenant_name = html.escape(tenant_name or "", quote=True)
    safe_error = html.escape(error or "", quote=True)

    payload = json.dumps({
        "type": "m365_consent_result",
        "success": success,
        "tenant_id": safe_tenant_id or None,
        "tenant_name": safe_tenant_name or None,
        "error": safe_error or None,
    })

    status_msg = "Connected successfully!" if success else "Connection failed."
    detail_msg = "You can close this window." if success else safe_error

    page = f"""<!DOCTYPE html>
<html>
<head><title>Microsoft 365 Setup</title></head>
<body>
<p>{status_msg}</p>
<p>{detail_msg}</p>
<script>
  if (window.opener) {{
    window.opener.postMessage({payload}, window.location.origin);
  }}
  setTimeout(function() {{ window.close(); }}, 1500);
</script>
</body>
</html>"""
    return HTMLResponse(content=page)
