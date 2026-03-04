"""WinRM-based remote audit configuration for agentless monitoring.

Connects to Windows file servers via WinRM (PowerShell Remoting) to:
1. Test connectivity and verify access
2. Configure SACL audit policies on file shares
3. Collect Security Event Log entries for file access events

Prerequisites on target servers:
- WinRM enabled (Enable-PSRemoting -Force)
- Port 5985 (HTTP) or 5986 (HTTPS) open
- Service account with SeSecurityPrivilege (manage audit policy)
- "Audit object access" enabled in Local Security Policy
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class WinRMResult:
    success: bool
    message: str
    data: dict | None = None
    error: str | None = None


def _validate_host(host: str) -> str:
    """Validate and sanitize WinRM host parameter to prevent injection.

    Also blocks private/internal IP ranges to prevent SSRF.
    """
    import ipaddress
    import re
    import socket

    # Allow only valid hostnames, FQDNs, and IPv4/IPv6 addresses
    if not re.match(r'^[a-zA-Z0-9._:\[\]-]+$', host):
        raise ValueError(f"Invalid WinRM host: {host!r}")
    if len(host) > 253:
        raise ValueError(f"WinRM host too long: {len(host)} chars")

    # Block private/internal IP ranges
    from openlabels.core.url_validation import _BLOCKED_NETWORKS

    try:
        addr_infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve WinRM host '{host}': {exc}") from exc

    for addr_info in addr_infos:
        ip_addr = ipaddress.ip_address(addr_info[4][0])
        for network in _BLOCKED_NETWORKS:
            if ip_addr in network:
                raise ValueError(
                    f"WinRM host '{host}' resolves to private/internal "
                    f"address ({network}), which is not allowed"
                )

    return host


def _get_winrm_session(
    host: str,
    username: str,
    password: str,
    use_ssl: bool = True,
    server_cert_validation: str = "validate",
):
    """Create a WinRM session to a remote host.

    Raises ImportError if pywinrm is not installed.

    Parameters
    ----------
    use_ssl:
        Use HTTPS transport (port 5986). Defaults to True for security.
        Set to False only for testing or when using Kerberos encryption.
    server_cert_validation:
        Certificate validation mode: ``"validate"`` (default, secure) or
        ``"ignore"`` (skip verification — use only for testing/self-signed
        certs).
    """
    import winrm  # pywinrm

    host = _validate_host(host)

    if not use_ssl:
        logger.warning(
            "SECURITY: WinRM connection to %s using unencrypted HTTP. "
            "Credentials will be transmitted in cleartext. "
            "Set use_ssl=True for production deployments.",
            host,
        )
        try:
            from openlabels.server.config import get_settings
            env = get_settings().server.environment
            if env in ("production", "staging"):
                raise ValueError(
                    f"Unencrypted WinRM (HTTP) is not allowed in {env}. "
                    "Set use_ssl=True."
                )
        except (ImportError, AttributeError):
            pass  # Settings may not be available in CLI context

    port = 5986 if use_ssl else 5985
    scheme = "https" if use_ssl else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"

    transport = "ntlm"
    # If the username contains @ it might be Kerberos
    if "@" in username and "\\" not in username:
        transport = "kerberos"

    return winrm.Session(
        endpoint,
        auth=(username, password),
        transport=transport,
        server_cert_validation=server_cert_validation,
        operation_timeout_sec=30,
        read_timeout_sec=35,
    )


async def test_connection(
    host: str,
    username: str,
    password: str,
    use_ssl: bool = True,
) -> WinRMResult:
    """Test WinRM connectivity and verify the account has audit privileges."""
    try:
        session = await asyncio.to_thread(
            _get_winrm_session, host, username, password, use_ssl
        )

        # Simple connectivity test + check audit privilege
        ps_script = """
$hostname = $env:COMPUTERNAME
$os = (Get-WmiObject Win32_OperatingSystem).Caption
$hasAuditPriv = (whoami /priv) -match 'SeSecurityPrivilege'
$auditEnabled = (auditpol /get /subcategory:"File System" 2>$null) -match 'Success'
@{
    hostname = $hostname
    os = $os
    has_audit_privilege = [bool]$hasAuditPriv
    audit_policy_enabled = [bool]$auditEnabled
} | ConvertTo-Json
"""
        result = await asyncio.to_thread(session.run_ps, ps_script)

        if result.status_code != 0:
            stderr = result.std_err.decode("utf-8", errors="replace").strip()
            return WinRMResult(
                success=False,
                message="Connected but command failed",
                error=stderr or "PowerShell execution failed",
            )

        import json

        stdout = result.std_out.decode("utf-8", errors="replace").strip()
        try:
            info = json.loads(stdout)
        except json.JSONDecodeError:
            info = {"raw_output": stdout}

        return WinRMResult(
            success=True,
            message=f"Connected to {info.get('hostname', host)}",
            data=info,
        )

    except ImportError:
        return WinRMResult(
            success=False,
            message="pywinrm is not installed",
            error="Install pywinrm: pip install pywinrm",
        )
    except Exception as e:
        logger.warning("WinRM connection to %s failed: %s", host, e)
        return WinRMResult(
            success=False,
            message="Connection failed",
            error=str(e),
        )


async def configure_audit_policy(
    host: str,
    username: str,
    password: str,
    share_paths: list[str],
    use_ssl: bool = True,
) -> WinRMResult:
    """Configure SACL audit rules on remote file shares via WinRM.

    Enables "Audit object access" subcategory for File System and adds
    SACL entries (Everyone → Read, Write → Success, Failure) on each
    share path.

    Args:
        host: Target file server hostname or IP.
        username: Account with SeSecurityPrivilege.
        password: Password.
        share_paths: List of local paths on the server to audit
                     (e.g. ["D:\\Shares\\Finance", "D:\\Shares\\HR"]).
        use_ssl: Use HTTPS transport (port 5986).

    Returns:
        WinRMResult with per-path success/failure details in data.
    """
    if not share_paths:
        return WinRMResult(success=False, message="No paths provided", error="share_paths is empty")

    try:
        session = await asyncio.to_thread(
            _get_winrm_session, host, username, password, use_ssl
        )

        # Build a PowerShell script that:
        # 1. Enables "Audit object access → File System" policy
        # 2. Adds SACL audit rules on each path
        # Each path is validated server-side via Test-Path.
        _INJECTION_CHARS = set('"\'`$\n\r;&|(){}%#<>')
        validated_paths = []
        for p in share_paths:
            if any(c in p for c in _INJECTION_CHARS):
                continue
            validated_paths.append(p)

        if not validated_paths:
            return WinRMResult(
                success=False,
                message="All paths rejected",
                error="Paths contain invalid characters",
            )

        path_array = ",\n".join(f'    "{p}"' for p in validated_paths)
        ps_script = f"""
# Enable audit policy for File System
auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null

$paths = @(
{path_array}
)
$results = @()
foreach ($p in $paths) {{
    if (-not (Test-Path $p)) {{
        $results += @{{ path = $p; status = "not_found" }}
        continue
    }}
    try {{
        $acl = Get-Acl -Path $p -Audit
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "Read, Write", "ContainerInherit, ObjectInherit",
            "None", "Success, Failure"
        )
        $acl.AddAuditRule($rule)
        Set-Acl -Path $p -AclObject $acl
        $results += @{{ path = $p; status = "configured" }}
    }} catch {{
        $results += @{{ path = $p; status = "failed"; error = $_.Exception.Message }}
    }}
}}
$results | ConvertTo-Json -Depth 3
"""

        result = await asyncio.to_thread(session.run_ps, ps_script)

        if result.status_code != 0:
            stderr = result.std_err.decode("utf-8", errors="replace").strip()
            return WinRMResult(
                success=False,
                message="Audit configuration failed",
                error=stderr,
            )

        import json

        stdout = result.std_out.decode("utf-8", errors="replace").strip()
        try:
            path_results = json.loads(stdout)
            if isinstance(path_results, dict):
                path_results = [path_results]
        except json.JSONDecodeError:
            path_results = [{"raw": stdout}]

        configured = sum(1 for r in path_results if r.get("status") == "configured")
        total = len(path_results)

        return WinRMResult(
            success=configured > 0,
            message=f"Configured audit on {configured}/{total} paths",
            data={"paths": path_results},
        )

    except ImportError:
        return WinRMResult(
            success=False,
            message="pywinrm is not installed",
            error="Install pywinrm: pip install pywinrm",
        )
    except Exception as e:
        logger.exception("Audit configuration failed for %s", host)
        return WinRMResult(success=False, message="Configuration failed", error=str(e))


async def collect_events(
    host: str,
    username: str,
    password: str,
    since_hours: int = 24,
    max_events: int = 500,
    use_ssl: bool = True,
) -> WinRMResult:
    """Collect file access events from a remote Windows Security Event Log.

    Queries events 4663 (object access) and 4656 (handle request) from
    the Security log via WinRM, filtered to the specified time window.

    Returns:
        WinRMResult with events list in data["events"].
    """
    # Validate parameters to prevent PowerShell injection
    if not isinstance(since_hours, int) or since_hours < 0:
        return WinRMResult(
            success=False,
            message="Invalid parameter",
            error="since_hours must be a non-negative integer",
        )
    if not isinstance(max_events, int) or max_events < 1:
        return WinRMResult(
            success=False,
            message="Invalid parameter",
            error="max_events must be a positive integer",
        )

    try:
        session = await asyncio.to_thread(
            _get_winrm_session, host, username, password, use_ssl
        )

        ps_script = f"""
$start = (Get-Date).AddHours(-{since_hours})
$events = Get-WinEvent -FilterHashtable @{{
    LogName = 'Security'
    Id = 4663, 4656
    StartTime = $start
}} -MaxEvents {max_events} -ErrorAction SilentlyContinue |
ForEach-Object {{
    [PSCustomObject]@{{
        time = $_.TimeCreated.ToString("o")
        event_id = $_.Id
        user_sid = $_.Properties[0].Value.ToString()
        user_name = $_.Properties[1].Value
        domain = $_.Properties[2].Value
        object_name = $_.Properties[6].Value
        access_mask = $_.Properties[8].Value
        process = $_.Properties[11].Value
    }}
}} | ConvertTo-Json -Depth 3
$events
"""

        result = await asyncio.to_thread(session.run_ps, ps_script)

        import json

        stdout = result.std_out.decode("utf-8", errors="replace").strip()

        if not stdout:
            return WinRMResult(
                success=True,
                message="No events found",
                data={"events": [], "host": host, "since_hours": since_hours},
            )

        try:
            events = json.loads(stdout)
            if isinstance(events, dict):
                events = [events]
        except json.JSONDecodeError:
            events = []

        return WinRMResult(
            success=True,
            message=f"Collected {len(events)} events from {host}",
            data={"events": events, "host": host, "since_hours": since_hours},
        )

    except ImportError:
        return WinRMResult(
            success=False,
            message="pywinrm is not installed",
            error="Install pywinrm: pip install pywinrm",
        )
    except Exception as e:
        logger.warning("Event collection from %s failed: %s", host, e)
        return WinRMResult(success=False, message="Event collection failed", error=str(e))
