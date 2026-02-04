"""
Server utility functions.

This module contains utility functions that need to be imported by multiple
modules. It's kept dependency-light to avoid circular imports.
"""

from fastapi import Request


def get_client_ip(request: Request) -> str:
    """
    Get real client IP address, handling proxies.

    Checks X-Forwarded-For header first (set by reverse proxies),
    then falls back to the direct client IP.

    Security note: X-Forwarded-For can be spoofed by clients.
    In production, configure your reverse proxy to overwrite
    (not append) this header with the actual client IP.
    """
    # Check X-Forwarded-For (standard proxy header)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (original client), stripping whitespace
        # Format: "client, proxy1, proxy2"
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP (nginx default)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fall back to direct client IP
    if request.client:
        return request.client.host

    return "127.0.0.1"
