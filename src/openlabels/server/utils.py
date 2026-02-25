"""
Server utility functions.

Kept dependency-light to avoid circular imports.
"""

from __future__ import annotations

import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from fastapi import Request

# Configurable list of trusted proxy IPs/CIDRs.  Only when the direct
# client IP (``request.client.host``) falls within one of these ranges
# will ``X-Forwarded-For`` / ``X-Real-IP`` headers be trusted.
#
# Populate at startup via ``configure_trusted_proxies()`` or by
# importing and mutating directly in tests.
#
# Examples:
#   - "127.0.0.1"       (single IPv4 loopback)
#   - "10.0.0.0/8"      (private RFC-1918 range)
#   - "::1"             (IPv6 loopback)
#   - "fd00::/8"        (IPv6 ULA range)
TRUSTED_PROXY_CIDRS: list[IPv4Network | IPv6Network] = []


def configure_trusted_proxies(cidrs: list[str]) -> None:
    """Replace the trusted-proxy list at runtime.

    Parameters
    ----------
    cidrs:
        IP addresses or CIDR ranges (e.g. ``["10.0.0.0/8", "172.16.0.0/12"]``).
        Single IPs are treated as /32 (IPv4) or /128 (IPv6) networks.
    """
    TRUSTED_PROXY_CIDRS.clear()
    for cidr in cidrs:
        TRUSTED_PROXY_CIDRS.append(ipaddress.ip_network(cidr, strict=False))


def _is_trusted_proxy(ip: str) -> bool:
    """Return ``True`` if *ip* is within any configured trusted proxy range."""
    if not TRUSTED_PROXY_CIDRS:
        return False
    try:
        addr: IPv4Address | IPv6Address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in TRUSTED_PROXY_CIDRS)


def get_client_ip(request: Request) -> str:
    """
    Get real client IP address, handling proxies.

    Only trusts ``X-Forwarded-For`` / ``X-Real-IP`` headers when the
    direct peer IP (the TCP connection source) is in the
    ``TRUSTED_PROXY_CIDRS`` list.  If no trusted proxies are configured,
    or the direct client is not a trusted proxy, the direct connection
    IP is returned — ignoring any forwarded headers that an untrusted
    client could have spoofed.
    """
    # Determine the direct peer IP from the TCP connection.
    direct_ip: str = request.client.host if request.client else "127.0.0.1"

    if not _is_trusted_proxy(direct_ip):
        # The immediate client is NOT a known proxy — do not trust any
        # forwarded headers; they could be attacker-controlled.
        return direct_ip

    # --- Direct client is a trusted proxy: honour forwarded headers ---

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

    # Trusted proxy but no forwarded header present — fall back to direct IP
    return direct_ip
