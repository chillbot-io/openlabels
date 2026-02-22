"""
Microsoft 365 admin consent and tenant connection management.

Implements the admin consent OAuth flow for connecting a customer's
M365 tenant to OpenLabels:

1. Admin clicks "Connect to Microsoft 365" in the setup wizard
2. Backend redirects to Microsoft's /adminconsent endpoint
3. Global Admin signs in and grants permissions to our multi-tenant app
4. Microsoft redirects back to our callback with tenant ID
5. Backend records the consent and verifies Graph API access
6. Wizard shows "Connected to <tenant>" with a green checkmark

After consent, OpenLabels uses client_credentials flow with its own
app registration (client_id + client_secret) against the consented
tenant to call Graph API for SharePoint/OneDrive enumeration and scanning.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import CurrentUser, require_admin
from openlabels.server.config import get_settings
from openlabels.server.db import get_session
from openlabels.server.routes import audit_log
from openlabels.server.session import SessionStore

logger = logging.getLogger(__name__)

router = APIRouter()

SESSION_COOKIE_NAME = "openlabels_session"

# Key in session data where we store the consent state nonce
_CONSENT_STATE_KEY = "m365_consent_state"
# Key in session data where we store the connected M365 tenant info
_M365_TENANT_KEY = "m365_tenant"


class M365StatusResponse(BaseModel):
    """Current M365 connection status."""
    connected: bool
    tenant_id: str | None = None
    tenant_name: str | None = None


class M365ConsentStartResponse(BaseModel):
    """Response with the admin consent URL."""
    consent_url: str


# ── Helpers ──────────────────────────────────────────────────────────

def _get_m365_config() -> tuple[str, str]:
    """Get the M365 app's client_id and client_secret from settings.

    Returns (client_id, client_secret). Raises 500 if not configured.
    """
    settings = get_settings()
    client_id = settings.m365.client_id
    client_secret = settings.m365.client_secret

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


async def _verify_graph_access(tenant_id: str) -> dict[str, Any] | None:
    """Verify we can access Graph API for the given tenant.

    Uses client_credentials flow with our app's credentials.
    Returns the organization info dict on success, None on failure.
    """
    client_id, client_secret = _get_m365_config()

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            token_resp = await client.post(token_url, data=token_data)
            if token_resp.status_code != 200:
                logger.warning(
                    "M365 token request failed for tenant %s: %s",
                    tenant_id, token_resp.text[:200],
                )
                return None

            access_token = token_resp.json()["access_token"]

            # Fetch organization info to get the tenant display name
            org_resp = await client.get(
                "https://graph.microsoft.com/v1.0/organization",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if org_resp.status_code != 200:
                # Token works but org endpoint failed — still connected
                return {"id": tenant_id, "displayName": tenant_id}

            orgs = org_resp.json().get("value", [])
            if orgs:
                return orgs[0]
            return {"id": tenant_id, "displayName": tenant_id}

    except httpx.HTTPError as e:
        logger.warning("M365 Graph API verification failed: %s", e)
        return None


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

    # Store the state nonce in the session for validation
    session_id, session_data = await _get_session_data(request, db)
    session_data[_CONSENT_STATE_KEY] = state
    await _save_session_data(db, session_id, session_data)

    # Build the admin consent URL
    # https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent
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
) -> HTMLResponse:
    """Handle the redirect from Microsoft's admin consent endpoint.

    This endpoint is loaded in a popup window. After processing,
    it renders a small HTML page that posts a message to the parent
    window and closes itself.
    """
    if error:
        logger.warning("M365 consent error: %s — %s", error, error_description)
        return _popup_response(
            success=False,
            error=error_description or error,
        )

    if not tenant or not state:
        return _popup_response(
            success=False,
            error="Missing tenant or state parameter",
        )

    if admin_consent != "True":
        return _popup_response(
            success=False,
            error="Admin consent was not granted",
        )

    # Validate state — we can't require auth here since this is a redirect
    # from Microsoft, but we validate the state nonce from the session
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return _popup_response(success=False, error="Session expired")

    store = SessionStore(db)
    session_data = await store.get(session_id)
    if not session_data:
        return _popup_response(success=False, error="Session expired")

    expected_state = session_data.get(_CONSENT_STATE_KEY)
    if not expected_state or expected_state != state:
        logger.warning("M365 consent state mismatch")
        return _popup_response(success=False, error="Invalid state")

    # Clear the state nonce
    session_data.pop(_CONSENT_STATE_KEY, None)

    # Verify we can actually access Graph API for this tenant
    org_info = await _verify_graph_access(tenant)
    if not org_info:
        return _popup_response(
            success=False,
            error="Consent was granted but Graph API access verification failed. "
                  "Permissions may still be propagating — try again in a few minutes.",
        )

    # Store the tenant connection info in the session
    tenant_name = org_info.get("displayName", tenant)
    session_data[_M365_TENANT_KEY] = {
        "tenant_id": tenant,
        "tenant_name": tenant_name,
    }
    await _save_session_data(db, session_id, session_data)

    logger.info("M365 consent granted for tenant %s (%s)", tenant, tenant_name)

    audit_log(
        db, tenant_id=None, user_id=None,
        action="settings_updated", resource_type="m365",
        details={"m365_tenant_id": tenant, "tenant_name": tenant_name},
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
    await _save_session_data(db, session_id, session_data)
    return {"status": "ok"}


# ── Popup response helper ────────────────────────────────────────────

def _popup_response(
    success: bool,
    tenant_id: str | None = None,
    tenant_name: str | None = None,
    error: str | None = None,
) -> HTMLResponse:
    """Return an HTML page that posts a message to the parent window and closes.

    The wizard's popup handler listens for this message to update the UI.
    """
    import json

    payload = json.dumps({
        "type": "m365_consent_result",
        "success": success,
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "error": error,
    })

    html = f"""<!DOCTYPE html>
<html>
<head><title>Microsoft 365 Setup</title></head>
<body>
<p>{"Connected successfully!" if success else "Connection failed."}</p>
<p>{"You can close this window." if success else (error or "")}</p>
<script>
  if (window.opener) {{
    window.opener.postMessage({payload}, window.location.origin);
  }}
  setTimeout(function() {{ window.close(); }}, 1500);
</script>
</body>
</html>"""
    return HTMLResponse(content=html)
