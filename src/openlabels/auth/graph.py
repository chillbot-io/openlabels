"""
Microsoft Graph API client using MSAL for authentication.

Provides server-to-server authentication using client credentials flow
for accessing Graph API to resolve user information, including SID lookups.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging

import httpx
from msal import ConfidentialClientApplication

from openlabels.server.config import get_settings

logger = logging.getLogger(__name__)

# Graph API base URL
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"

# Scopes for client credentials flow (no user context)
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]


@dataclass
class GraphUser:
    """User information from Microsoft Graph."""

    id: str  # Entra object ID (GUID)
    display_name: Optional[str] = None
    user_principal_name: Optional[str] = None  # email/UPN
    mail: Optional[str] = None
    given_name: Optional[str] = None
    surname: Optional[str] = None
    job_title: Optional[str] = None
    department: Optional[str] = None
    office_location: Optional[str] = None
    on_premises_sam_account_name: Optional[str] = None  # DOMAIN\username style
    on_premises_security_identifier: Optional[str] = None  # On-prem SID

    @property
    def best_display_name(self) -> str:
        """Get the best available display name."""
        return (
            self.display_name
            or self.user_principal_name
            or self.on_premises_sam_account_name
            or self.id
        )

    @property
    def domain_username(self) -> Optional[str]:
        """Get DOMAIN\\username format if available."""
        return self.on_premises_sam_account_name


class GraphClient:
    """
    Microsoft Graph API client with MSAL authentication.

    Uses client credentials flow for server-to-server authentication.
    Requires app registration with appropriate permissions:
    - User.Read.All (for user lookups)
    - Directory.Read.All (for broader directory queries)
    """

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        """
        Initialize Graph client.

        If credentials not provided, loads from settings.
        """
        settings = get_settings()

        self.tenant_id = tenant_id or settings.auth.tenant_id
        self.client_id = client_id or settings.auth.client_id
        self.client_secret = client_secret or settings.auth.client_secret

        if not all([self.tenant_id, self.client_id, self.client_secret]):
            raise ValueError(
                "Graph client requires tenant_id, client_id, and client_secret. "
                "Set AUTH_TENANT_ID, AUTH_CLIENT_ID, AUTH_CLIENT_SECRET environment variables."
            )

        # Initialize MSAL confidential client
        self._msal_app = ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )

        # Token cache
        self._access_token: Optional[str] = None
        self._token_expires: Optional[datetime] = None

    async def _get_access_token(self) -> str:
        """Get access token, refreshing if needed."""
        # Check if we have a valid cached token
        if self._access_token and self._token_expires:
            if datetime.now(timezone.utc) < self._token_expires - timedelta(minutes=5):
                return self._access_token

        # Acquire new token
        result = self._msal_app.acquire_token_for_client(scopes=GRAPH_SCOPES)

        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "Unknown error"))
            raise RuntimeError(f"Failed to acquire Graph API token: {error}")

        self._access_token = result["access_token"]
        # Token typically valid for 1 hour
        expires_in = result.get("expires_in", 3600)
        self._token_expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        logger.debug("Acquired new Graph API access token")
        return self._access_token

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
    ) -> dict:
        """Make authenticated request to Graph API."""
        token = await self._get_access_token()

        url = f"{GRAPH_API_BASE}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json,
                timeout=30.0,
            )

            if response.status_code == 404:
                return {}

            response.raise_for_status()
            return response.json()

    async def get_user_by_id(self, user_id: str) -> Optional[GraphUser]:
        """
        Get user by Entra object ID.

        Args:
            user_id: Entra object ID (GUID)

        Returns:
            GraphUser or None if not found
        """
        try:
            data = await self._request(
                "GET",
                f"/users/{user_id}",
                params={
                    "$select": "id,displayName,userPrincipalName,mail,givenName,surname,"
                    "jobTitle,department,officeLocation,"
                    "onPremisesSamAccountName,onPremisesSecurityIdentifier"
                },
            )

            if not data or "id" not in data:
                return None

            return self._parse_user(data)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            logger.error(f"Failed to get user {user_id}: {e}")
            raise

    async def get_user_by_upn(self, upn: str) -> Optional[GraphUser]:
        """
        Get user by User Principal Name (email).

        Args:
            upn: User Principal Name (e.g., user@contoso.com)

        Returns:
            GraphUser or None if not found
        """
        try:
            data = await self._request(
                "GET",
                f"/users/{upn}",
                params={
                    "$select": "id,displayName,userPrincipalName,mail,givenName,surname,"
                    "jobTitle,department,officeLocation,"
                    "onPremisesSamAccountName,onPremisesSecurityIdentifier"
                },
            )

            if not data or "id" not in data:
                return None

            return self._parse_user(data)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            logger.error(f"Failed to get user by UPN {upn}: {e}")
            raise

    async def get_user_by_on_prem_sid(self, sid: str) -> Optional[GraphUser]:
        """
        Get user by on-premises Security Identifier (SID).

        This is the key method for resolving Windows file access SIDs
        to actual user information in hybrid environments.

        Args:
            sid: Windows SID (e.g., S-1-5-21-3623811015-3361044348-30300820-1013)

        Returns:
            GraphUser or None if not found
        """
        try:
            # Use $filter to find user by onPremisesSecurityIdentifier
            data = await self._request(
                "GET",
                "/users",
                params={
                    "$filter": f"onPremisesSecurityIdentifier eq '{sid}'",
                    "$select": "id,displayName,userPrincipalName,mail,givenName,surname,"
                    "jobTitle,department,officeLocation,"
                    "onPremisesSamAccountName,onPremisesSecurityIdentifier",
                },
            )

            users = data.get("value", [])
            if not users:
                return None

            return self._parse_user(users[0])

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to get user by SID {sid}: {e}")
            raise

    async def get_user_by_sam_account_name(self, sam_account_name: str) -> Optional[GraphUser]:
        """
        Get user by on-premises SAM account name.

        Args:
            sam_account_name: SAM account name (e.g., jsmith or DOMAIN\\jsmith)

        Returns:
            GraphUser or None if not found
        """
        # Strip domain prefix if present
        if "\\" in sam_account_name:
            sam_account_name = sam_account_name.split("\\")[1]

        try:
            data = await self._request(
                "GET",
                "/users",
                params={
                    "$filter": f"onPremisesSamAccountName eq '{sam_account_name}'",
                    "$select": "id,displayName,userPrincipalName,mail,givenName,surname,"
                    "jobTitle,department,officeLocation,"
                    "onPremisesSamAccountName,onPremisesSecurityIdentifier",
                },
            )

            users = data.get("value", [])
            if not users:
                return None

            return self._parse_user(users[0])

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to get user by SAM account name {sam_account_name}: {e}")
            raise

    async def search_users(self, query: str, limit: int = 10) -> list[GraphUser]:
        """
        Search for users by display name or email.

        Args:
            query: Search query
            limit: Maximum results to return

        Returns:
            List of matching users
        """
        try:
            data = await self._request(
                "GET",
                "/users",
                params={
                    "$filter": f"startswith(displayName, '{query}') or "
                    f"startswith(userPrincipalName, '{query}')",
                    "$select": "id,displayName,userPrincipalName,mail,givenName,surname,"
                    "onPremisesSamAccountName,onPremisesSecurityIdentifier",
                    "$top": str(limit),
                },
            )

            return [self._parse_user(u) for u in data.get("value", [])]

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to search users: {e}")
            raise

    def _parse_user(self, data: dict) -> GraphUser:
        """Parse Graph API user response into GraphUser object."""
        return GraphUser(
            id=data["id"],
            display_name=data.get("displayName"),
            user_principal_name=data.get("userPrincipalName"),
            mail=data.get("mail"),
            given_name=data.get("givenName"),
            surname=data.get("surname"),
            job_title=data.get("jobTitle"),
            department=data.get("department"),
            office_location=data.get("officeLocation"),
            on_premises_sam_account_name=data.get("onPremisesSamAccountName"),
            on_premises_security_identifier=data.get("onPremisesSecurityIdentifier"),
        )


# Singleton instance
_graph_client: Optional[GraphClient] = None


def get_graph_client() -> GraphClient:
    """Get or create singleton Graph client."""
    global _graph_client

    if _graph_client is None:
        settings = get_settings()
        if settings.auth.provider == "none":
            raise RuntimeError(
                "Graph client requires Azure AD authentication. "
                "Set AUTH_PROVIDER=azure_ad and configure credentials."
            )
        _graph_client = GraphClient()

    return _graph_client


def reset_graph_client():
    """Reset singleton (useful for testing)."""
    global _graph_client
    _graph_client = None
