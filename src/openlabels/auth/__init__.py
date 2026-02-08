"""
Authentication and authorization module.

Provides:
- OAuth 2.0 / OIDC authentication with Microsoft Entra ID
- Microsoft Graph API client for user lookups
- SID (Security Identifier) resolution for file access monitoring
"""

# Lazy imports to avoid loading heavy dependencies when not needed
# This allows importing auth.sid_resolver without loading cryptography


def __getattr__(name: str):
    """Lazy import to avoid loading heavy dependencies."""
    if name == "validate_token":
        from openlabels.auth.oauth import validate_token
        return validate_token
    elif name == "get_current_user":
        from openlabels.auth.dependencies import get_current_user
        return get_current_user
    elif name == "require_admin":
        from openlabels.auth.dependencies import require_admin
        return require_admin
    elif name == "require_role":
        from openlabels.auth.dependencies import require_role
        return require_role
    elif name == "require_operator":
        from openlabels.auth.dependencies import require_operator
        return require_operator
    elif name == "require_viewer":
        from openlabels.auth.dependencies import require_viewer
        return require_viewer
    elif name == "resolve_sid":
        from openlabels.auth.sid_resolver import resolve_sid
        return resolve_sid
    elif name == "resolve_sid_sync":
        from openlabels.auth.sid_resolver import resolve_sid_sync
        return resolve_sid_sync
    elif name == "is_system_account_sid":
        from openlabels.auth.sid_resolver import is_system_account_sid
        return is_system_account_sid
    elif name == "get_sid_resolver":
        from openlabels.auth.sid_resolver import get_sid_resolver
        return get_sid_resolver
    elif name == "ResolvedUser":
        from openlabels.auth.sid_resolver import ResolvedUser
        return ResolvedUser
    elif name == "GraphClient":
        from openlabels.auth.graph import GraphClient
        return GraphClient
    elif name == "get_graph_client":
        from openlabels.auth.graph import get_graph_client
        return get_graph_client

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # OAuth
    "validate_token",
    "get_current_user",
    "require_admin",
    "require_role",
    "require_operator",
    "require_viewer",
    # SID Resolution
    "resolve_sid",
    "resolve_sid_sync",
    "is_system_account_sid",
    "get_sid_resolver",
    "ResolvedUser",
    # Graph API
    "GraphClient",
    "get_graph_client",
]
