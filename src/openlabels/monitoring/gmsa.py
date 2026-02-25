"""Group Managed Service Account (gMSA) detection and setup helpers.

Provides runtime detection of whether the OpenLabels process is running
as a gMSA and generates PowerShell setup scripts for domain admins.

gMSA eliminates static service account passwords — Active Directory
manages password rotation automatically.  Combined with WEF (which uses
Kerberos machine auth for event delivery), this removes all stored
credentials from the monitoring pipeline.

Architecture::

    AD Domain Controller
        ├── manages gMSA password (auto-rotated every 30 days)
        └── issues Kerberos tickets for machine auth (WEF)

    OpenLabels (runs as gMSA)
        ├── WEC service accepts events via Kerberos
        └── no stored passwords anywhere

    File Servers (domain-joined)
        ├── push events via WEF (machine Kerberos)
        └── audit policy deployed via GPO
"""

from __future__ import annotations

import logging
import os
import sys
import textwrap
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ServiceIdentity:
    """Information about the identity running the OpenLabels process."""

    account_name: str
    domain: str | None
    is_gmsa: bool
    is_local_system: bool
    is_network_service: bool
    sid: str | None = None


def detect_service_identity() -> ServiceIdentity:
    """Detect the Windows account running this process.

    On Windows, uses the win32 API to get the process token owner.
    On non-Windows, returns a placeholder with the Unix username.
    """
    if sys.platform != "win32":
        import getpass
        username = getpass.getuser()
        return ServiceIdentity(
            account_name=username,
            domain=None,
            is_gmsa=False,
            is_local_system=False,
            is_network_service=False,
        )

    # Windows: try to detect via environment and process token
    username = os.environ.get("USERNAME", "")
    userdomain = os.environ.get("USERDOMAIN", "")

    # gMSA account names end with '$'
    is_gmsa = username.endswith("$")

    # Well-known accounts
    is_local_system = username.upper() == "SYSTEM"
    is_network_service = username.upper() in ("NETWORK SERVICE", "NETWORKSERVICE")

    sid = None
    try:
        # Try to get the SID via WMI (no extra dependencies)
        import subprocess
        proc = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            # Output: "DOMAIN\user","S-1-5-..."
            parts = proc.stdout.strip().split(",")
            if len(parts) >= 2:
                sid = parts[-1].strip().strip('"')
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return ServiceIdentity(
        account_name=username,
        domain=userdomain or None,
        is_gmsa=is_gmsa,
        is_local_system=is_local_system,
        is_network_service=is_network_service,
        sid=sid,
    )


def _ps_escape(value: str) -> str:
    """Escape a string for safe embedding in a PowerShell double-quoted string.

    Escapes backticks, dollar signs, and double quotes which are the
    special characters inside PowerShell double-quoted strings.
    """
    return (
        value
        .replace('`', '``')    # backtick is the PS escape char
        .replace('"', '`"')    # escape double quotes
        .replace('$', '`$')    # escape variable expansion
    )


def generate_gmsa_setup_script(
    *,
    account_name: str = "svc-openlabels",
    dns_hostname: str = "",
    server_group: str = "OpenLabels-Servers",
    domain: str = "",
) -> str:
    """Generate PowerShell commands to create a gMSA for OpenLabels.

    The admin runs these on a Domain Controller (or any machine with
    the AD PowerShell module).  The output is a complete script that:

    1. Creates a security group for OpenLabels server(s)
    2. Creates the gMSA
    3. Installs the gMSA on the target server
    4. Configures the OpenLabels Windows service to run as the gMSA

    Parameters
    ----------
    account_name:
        The gMSA sAMAccountName (without trailing $).
    dns_hostname:
        FQDN for the gMSA's service principal.  If empty, uses
        ``account_name.<domain>``.
    server_group:
        AD security group whose members can retrieve the gMSA password.
    domain:
        Domain DNS name.  If empty, uses the current domain.
    """
    acct = _ps_escape(account_name.rstrip("$"))

    dns = dns_hostname or (f"{acct}.{domain}" if domain else f"{acct}.$env:USERDNSDOMAIN")
    dns = _ps_escape(dns) if dns_hostname else dns  # Only escape user-provided hostnames
    group = _ps_escape(server_group)
    fqdn_note = f"  # → {dns}" if dns_hostname else ""

    return textwrap.dedent(f"""\
        # ═══════════════════════════════════════════════════════════════
        # OpenLabels — gMSA Setup Script
        #
        # Run on a Domain Controller (or machine with RSAT AD tools).
        # Requires Enterprise/Domain Admin privileges.
        # ═══════════════════════════════════════════════════════════════

        Import-Module ActiveDirectory

        # ── Step 1: Create KDS root key (one-time, domain-wide) ──────
        # If this is the first gMSA in the domain, create the KDS root
        # key.  The -EffectiveImmediately flag makes it usable after
        # ~10 hours of replication.  In a lab, use -EffectiveTime with
        # a past date to skip the wait.
        if (-not (Get-KdsRootKey)) {{
            Add-KdsRootKey -EffectiveImmediately
            Write-Host "KDS root key created. Wait ~10h for replication before proceeding." -ForegroundColor Yellow
        }} else {{
            Write-Host "KDS root key already exists." -ForegroundColor Green
        }}

        # ── Step 2: Create security group for OpenLabels servers ─────
        $GroupName = "{group}"
        if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue)) {{
            New-ADGroup -Name $GroupName `
                -GroupScope Global `
                -GroupCategory Security `
                -Description "Servers allowed to use the OpenLabels gMSA"
            Write-Host "Created group: $GroupName"
        }}

        # Add this server to the group (run on each OpenLabels host)
        $Computer = Get-ADComputer $env:COMPUTERNAME
        Add-ADGroupMember -Identity $GroupName -Members $Computer
        Write-Host "Added $($Computer.Name) to $GroupName"

        # ── Step 3: Create the gMSA ─────────────────────────────────
        $AccountName = "{acct}"
        $DnsHostName = "{dns}"{fqdn_note}

        New-ADServiceAccount -Name $AccountName `
            -DNSHostName $DnsHostName `
            -PrincipalsAllowedToRetrieveManagedPassword $GroupName `
            -Description "OpenLabels file monitoring service account"

        Write-Host "Created gMSA: $AccountName$" -ForegroundColor Green

        # ── Step 4: Install gMSA on this server ─────────────────────
        # Run this step on each OpenLabels server.
        Install-ADServiceAccount -Identity $AccountName
        Test-ADServiceAccount -Identity $AccountName

        # ── Step 5: Configure the OpenLabels service ─────────────────
        # If running OpenLabels as a Windows service:
        # sc.exe config "OpenLabels" obj="$env:USERDOMAIN\\$AccountName$" type=own
        #
        # The gMSA password is retrieved automatically from AD.
        # No password is stored or configured anywhere.

        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  gMSA '$AccountName$' is ready." -ForegroundColor Cyan
        Write-Host "  Restart the OpenLabels service to apply." -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    """)


def generate_audit_gpo_script(
    *,
    share_paths: list[str] | None = None,
) -> str:
    """Generate PowerShell for configuring file access audit policy via GPO.

    This replaces the WinRM-based SACL configuration with a GPO-deployed
    approach.  The admin deploys this once and it applies to all file
    servers in the targeted OU.

    Two things need to happen:
    1. Enable "Audit File System" (Advanced Audit Policy)
    2. Set SACLs on the file share paths (GPO Preferences or script)
    """
    # Build SACL commands for specific paths
    sacl_lines = ""
    if share_paths:
        path_cmds = []
        for path in share_paths:
            # Escape for PowerShell double-quoted string context:
            # backticks, dollar signs, and double quotes are special.
            safe_path = _ps_escape(path)
            path_cmds.append(
                f'    Set-AuditRule -Path "{safe_path}"'
            )
        sacl_lines = "\n".join(path_cmds)

    # Pre-compute the example/placeholder lines (backslashes can't go
    # inside f-string expressions in older Python versions).
    example_line = '        # Set-AuditRule -Path "D:\\Shares\\Finance"'
    extra_comment = "        # Add more paths as needed:"
    extra_example = '        # Set-AuditRule -Path "D:\\Shares\\HR"'

    if sacl_lines:
        path_block = sacl_lines
    else:
        path_block = f"{example_line}\n{extra_comment}\n{extra_example}"

    return textwrap.dedent(f"""\
        # ═══════════════════════════════════════════════════════════════
        # OpenLabels — File Access Audit Policy Setup
        #
        # Deploy via GPO startup script, or run directly on file servers.
        # This enables audit logging so WEF can forward the events.
        # ═══════════════════════════════════════════════════════════════

        # ── Step 1: Enable Advanced Audit Policy ─────────────────────
        # Enable "Audit File System" for Success and Failure events.
        # This is the policy equivalent of:
        #   Computer Configuration > Windows Settings > Security Settings >
        #   Advanced Audit Policy > Object Access > Audit File System
        auditpol /set /subcategory:"File System" /success:enable /failure:enable

        if ($LASTEXITCODE -eq 0) {{
            Write-Host "Audit File System policy enabled (success + failure)"
        }} else {{
            Write-Error "Failed to set audit policy. Run as Administrator."
            exit 1
        }}

        # ── Step 2: Set SACLs on monitored paths ────────────────────
        # Adds an audit ACE for Everyone (Success + Failure) on each path.
        # This makes Windows generate event 4663 when files are accessed.

        function Set-AuditRule {{
            param([string]$Path)
            if (-not (Test-Path $Path)) {{
                Write-Warning "Path not found: $Path"
                return
            }}
            $acl = Get-Acl $Path -Audit
            $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone",
                "ReadData, WriteData, Delete",
                "ContainerInherit, ObjectInherit",
                "None",
                "Success, Failure"
            )
            $acl.AddAuditRule($rule)
            Set-Acl -Path $Path -AclObject $acl
            Write-Host "SACL configured on: $Path"
        }}
{path_block}

        Write-Host ""
        Write-Host "Audit policy configured. Events will appear in the Security log."
        Write-Host "WEF will forward them to the OpenLabels collector automatically."
    """)
