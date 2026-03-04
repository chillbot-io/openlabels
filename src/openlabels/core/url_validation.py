"""URL validation for preventing SSRF attacks.

Provides a reusable ``validate_url`` function that resolves hostnames and
rejects URLs pointing to private/internal IP ranges.  Used by export
adapters (Splunk, Elasticsearch) and cloud adapters (S3) to block
Server-Side Request Forgery.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Private / internal IP networks that must never be reached
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fd00::/8"),
]


def validate_url(url: str, *, name: str = "URL") -> str:
    """Validate that a URL does not target private/internal IPs.

    Parses the URL, resolves the hostname, and rejects URLs where any
    resolved address falls within a blocked IP range.

    Args:
        url: The URL to validate.
        name: Human-readable name for error messages (e.g. "HEC URL").

    Returns:
        The validated URL (unchanged) if it passes all checks.

    Raises:
        ValueError: If the URL is malformed, unresolvable, or targets
            a blocked network.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"Invalid {name}: {exc}") from exc

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"{name} must use http or https scheme, got '{parsed.scheme}'"
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"{name} is missing a hostname")

    try:
        addr_infos = socket.getaddrinfo(
            hostname, parsed.port or 443, proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise ValueError(
            f"Cannot resolve {name} hostname '{hostname}': {exc}"
        ) from exc

    if not addr_infos:
        raise ValueError(
            f"Cannot resolve {name} hostname '{hostname}': no addresses found"
        )

    for addr_info in addr_infos:
        ip_str = addr_info[4][0]
        ip_addr = ipaddress.ip_address(ip_str)
        for network in _BLOCKED_NETWORKS:
            if ip_addr in network:
                raise ValueError(
                    f"{name} hostname '{hostname}' resolves to private/internal "
                    f"address {ip_str} (in {network}). This is not allowed."
                )

    return url


def validate_host(host: str, port: int, *, name: str = "host") -> str:
    """Validate that a hostname/IP does not target private/internal addresses.

    Same SSRF protection as ``validate_url`` but for raw host:port used by
    syslog-based adapters (QRadar, generic syslog/CEF).

    Returns:
        The validated hostname if it passes all checks.

    Raises:
        ValueError: If the host is unresolvable or targets a blocked network.
    """
    if not host:
        raise ValueError(f"{name} must not be empty")

    try:
        addr_infos = socket.getaddrinfo(
            host, port, proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise ValueError(
            f"Cannot resolve {name} '{host}': {exc}"
        ) from exc

    if not addr_infos:
        raise ValueError(
            f"Cannot resolve {name} '{host}': no addresses found"
        )

    for addr_info in addr_infos:
        ip_str = addr_info[4][0]
        ip_addr = ipaddress.ip_address(ip_str)
        for network in _BLOCKED_NETWORKS:
            if ip_addr in network:
                raise ValueError(
                    f"{name} '{host}' resolves to private/internal "
                    f"address {ip_str} (in {network}). This is not allowed."
                )

    return host
