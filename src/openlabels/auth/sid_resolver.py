"""
SID (Security Identifier) to user resolution with caching.

Resolves Windows SIDs to human-readable user information using Microsoft Graph API.
Supports both cloud-only and hybrid (on-prem synced) Entra ID environments.

Features:
- In-memory LRU cache for performance
- Optional database persistence for resolved SIDs
- Well-known SID handling (SYSTEM, LOCAL SERVICE, etc.)
- Graceful fallback when Graph API unavailable
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class ResolvedUser:
    """Resolved user information from a SID."""

    sid: str
    display_name: Optional[str] = None
    user_principal_name: Optional[str] = None  # email
    domain_username: Optional[str] = None  # DOMAIN\username
    entra_object_id: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    is_well_known: bool = False
    is_system_account: bool = False
    resolved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolution_source: str = "unknown"  # "graph_api", "well_known", "cache", "fallback"

    @property
    def best_name(self) -> str:
        """Get the best available name for display."""
        return (
            self.display_name
            or self.domain_username
            or self.user_principal_name
            or self.sid
        )


# Well-known Windows SIDs
# https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
WELL_KNOWN_SIDS = {
    # Universal well-known SIDs
    "S-1-0-0": ("Nobody", True),
    "S-1-1-0": ("Everyone", False),
    "S-1-2-0": ("Local", True),
    "S-1-2-1": ("Console Logon", False),
    "S-1-3-0": ("Creator Owner", False),
    "S-1-3-1": ("Creator Group", False),
    "S-1-3-4": ("Owner Rights", False),
    "S-1-5-1": ("Dialup", False),
    "S-1-5-2": ("Network", False),
    "S-1-5-3": ("Batch", False),
    "S-1-5-4": ("Interactive", False),
    "S-1-5-6": ("Service", True),
    "S-1-5-7": ("Anonymous", True),
    "S-1-5-9": ("Enterprise Domain Controllers", True),
    "S-1-5-10": ("Principal Self", False),
    "S-1-5-11": ("Authenticated Users", False),
    "S-1-5-12": ("Restricted Code", True),
    "S-1-5-13": ("Terminal Server Users", False),
    "S-1-5-14": ("Remote Interactive Logon", False),
    "S-1-5-15": ("This Organization", False),
    "S-1-5-17": ("IUSR", True),
    "S-1-5-18": ("Local System", True),
    "S-1-5-19": ("NT Authority\\Local Service", True),
    "S-1-5-20": ("NT Authority\\Network Service", True),
    # Built-in domain SIDs (relative to domain)
    "S-1-5-32-544": ("BUILTIN\\Administrators", True),
    "S-1-5-32-545": ("BUILTIN\\Users", False),
    "S-1-5-32-546": ("BUILTIN\\Guests", False),
    "S-1-5-32-547": ("BUILTIN\\Power Users", False),
    "S-1-5-32-548": ("BUILTIN\\Account Operators", True),
    "S-1-5-32-549": ("BUILTIN\\Server Operators", True),
    "S-1-5-32-550": ("BUILTIN\\Print Operators", True),
    "S-1-5-32-551": ("BUILTIN\\Backup Operators", True),
    "S-1-5-32-552": ("BUILTIN\\Replicators", True),
}

# Patterns for identifying system accounts by SID suffix
SYSTEM_ACCOUNT_RID_SUFFIXES = {
    "-500": "Administrator",
    "-501": "Guest",
    "-502": "KRBTGT",
    "-512": "Domain Admins",
    "-513": "Domain Users",
    "-514": "Domain Guests",
    "-515": "Domain Computers",
    "-516": "Domain Controllers",
    "-517": "Cert Publishers",
    "-518": "Schema Admins",
    "-519": "Enterprise Admins",
    "-520": "Group Policy Creator Owners",
}


class SIDResolver:
    """
    Resolve Windows SIDs to user information.

    Uses Microsoft Graph API for hybrid/cloud users with local caching.
    """

    def __init__(
        self,
        cache_ttl_hours: int = 24,
        max_cache_size: int = 10000,
        enable_graph: bool = True,
    ):
        """
        Initialize SID resolver.

        Args:
            cache_ttl_hours: How long to cache resolved SIDs
            max_cache_size: Maximum cache entries
            enable_graph: Whether to use Graph API for resolution
        """
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.max_cache_size = max_cache_size
        self.enable_graph = enable_graph

        # In-memory cache: SID -> (ResolvedUser, timestamp)
        self._cache: dict[str, tuple[ResolvedUser, datetime]] = {}

        # Graph client (lazy initialized)
        self._graph_client = None

    def _get_graph_client(self):
        """Get Graph client, initializing if needed."""
        if self._graph_client is None and self.enable_graph:
            try:
                from openlabels.auth.graph import get_graph_client
                self._graph_client = get_graph_client()
            except (ImportError, RuntimeError, OSError) as e:
                logger.warning(f"Failed to initialize Graph client: {e}")
                # Don't permanently disable — transient errors (network blips,
                # service restarts) should not require a process restart to recover.
                return None
        return self._graph_client

    def _check_well_known(self, sid: str) -> Optional[ResolvedUser]:
        """Check if SID is a well-known SID."""
        if sid in WELL_KNOWN_SIDS:
            name, is_system = WELL_KNOWN_SIDS[sid]
            return ResolvedUser(
                sid=sid,
                display_name=name,
                is_well_known=True,
                is_system_account=is_system,
                resolution_source="well_known",
            )

        # Check for domain-relative well-known accounts
        for suffix, name in SYSTEM_ACCOUNT_RID_SUFFIXES.items():
            if sid.endswith(suffix):
                return ResolvedUser(
                    sid=sid,
                    display_name=name,
                    is_well_known=True,
                    is_system_account=True,
                    resolution_source="well_known",
                )

        return None

    def _check_cache(self, sid: str) -> Optional[ResolvedUser]:
        """Check if SID is in cache and not expired."""
        if sid in self._cache:
            user, cached_at = self._cache[sid]
            if datetime.now(timezone.utc) - cached_at < self.cache_ttl:
                user.resolution_source = "cache"
                return user
            else:
                # Expired - remove from cache
                del self._cache[sid]
        return None

    def _add_to_cache(self, user: ResolvedUser):
        """Add resolved user to cache."""
        # Evict oldest entries if cache is full
        if len(self._cache) >= self.max_cache_size:
            # Remove oldest 10%
            entries = sorted(self._cache.items(), key=lambda x: x[1][1])
            for sid, _ in entries[: self.max_cache_size // 10]:
                del self._cache[sid]

        self._cache[user.sid] = (user, datetime.now(timezone.utc))

    async def resolve(self, sid: str) -> ResolvedUser:
        """
        Resolve a SID to user information.

        Resolution order:
        1. Well-known SIDs (SYSTEM, LOCAL SERVICE, etc.)
        2. In-memory cache
        3. Microsoft Graph API (for hybrid/cloud users)
        4. Fallback (returns SID as display name)

        Args:
            sid: Windows Security Identifier

        Returns:
            ResolvedUser with available information
        """
        # Normalize SID
        sid = sid.strip().upper()
        if not sid.startswith("S-1-"):
            # Not a valid SID format
            return ResolvedUser(
                sid=sid,
                display_name=sid,
                resolution_source="invalid",
            )

        # 1. Check well-known SIDs
        well_known = self._check_well_known(sid)
        if well_known:
            return well_known

        # 2. Check cache
        cached = self._check_cache(sid)
        if cached:
            return cached

        # 3. Try Graph API
        if self.enable_graph:
            try:
                graph = self._get_graph_client()
                if graph:
                    graph_user = await graph.get_user_by_on_prem_sid(sid)
                    if graph_user:
                        resolved = ResolvedUser(
                            sid=sid,
                            display_name=graph_user.display_name,
                            user_principal_name=graph_user.user_principal_name,
                            domain_username=graph_user.on_premises_sam_account_name,
                            entra_object_id=graph_user.id,
                            department=graph_user.department,
                            job_title=graph_user.job_title,
                            is_system_account=False,
                            resolution_source="graph_api",
                        )
                        self._add_to_cache(resolved)
                        return resolved
            except (OSError, RuntimeError, ValueError, KeyError, AttributeError) as e:
                logger.warning(f"Graph API resolution failed for SID {sid}: {e}")

        # 4. Fallback - return SID as name
        fallback = ResolvedUser(
            sid=sid,
            display_name=sid,
            resolution_source="fallback",
        )
        # Cache fallback briefly (1 hour) to avoid repeated failed lookups
        self._cache[sid] = (fallback, datetime.now(timezone.utc))
        return fallback

    async def resolve_batch(self, sids: list[str]) -> dict[str, ResolvedUser]:
        """
        Resolve multiple SIDs.

        Args:
            sids: List of SIDs to resolve

        Returns:
            Dict mapping SID -> ResolvedUser
        """
        results = {}
        for sid in sids:
            results[sid] = await self.resolve(sid)
        return results

    def resolve_sync(self, sid: str) -> ResolvedUser:
        """
        Synchronous version of resolve (no Graph API lookup).

        Only checks well-known SIDs and cache.
        For full resolution, use async resolve().
        """
        sid = sid.strip().upper()

        # Check well-known
        well_known = self._check_well_known(sid)
        if well_known:
            return well_known

        # Check cache
        cached = self._check_cache(sid)
        if cached:
            return cached

        # Fallback
        return ResolvedUser(
            sid=sid,
            display_name=sid,
            resolution_source="fallback_sync",
        )

    def clear_cache(self):
        """Clear the resolution cache."""
        self._cache.clear()

    def get_cache_stats(self) -> dict:
        """Get cache statistics."""
        now = datetime.now(timezone.utc)
        valid = sum(1 for _, (_, ts) in self._cache.items() if now - ts < self.cache_ttl)
        return {
            "total_entries": len(self._cache),
            "valid_entries": valid,
            "expired_entries": len(self._cache) - valid,
            "max_size": self.max_cache_size,
        }


# Singleton instance
_resolver: Optional[SIDResolver] = None


def get_sid_resolver() -> SIDResolver:
    """Get or create singleton SID resolver."""
    global _resolver
    if _resolver is None:
        _resolver = SIDResolver()
    return _resolver


def reset_sid_resolver():
    """Reset singleton (useful for testing)."""
    global _resolver
    _resolver = None


# Convenience function
async def resolve_sid(sid: str) -> ResolvedUser:
    """Resolve a single SID using the singleton resolver."""
    return await get_sid_resolver().resolve(sid)


def resolve_sid_sync(sid: str) -> ResolvedUser:
    """Resolve a single SID synchronously (cache/well-known only)."""
    return get_sid_resolver().resolve_sync(sid)


def is_system_account_sid(sid: str) -> bool:
    """Quick check if a SID is a system account."""
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid][1]

    for suffix in SYSTEM_ACCOUNT_RID_SUFFIXES:
        if sid.endswith(suffix):
            return True

    return False
