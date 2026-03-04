"""Windows Event Forwarding (WEF) subscription management.

Configures the OpenLabels server as a Windows Event Collector (WEC)
that receives file access events (4663/4656) from remote file servers
via source-initiated subscriptions.

Architecture::

    File Server A ──push──→
    File Server B ──push──→  OpenLabels (WEC)  → ForwardedEvents log
    File Server C ──push──→                       → WEFProvider reads

Setup requires two steps:
1. Run ``create_subscription()`` on the OpenLabels server (creates
   the WEC subscription via ``wecutil``).
2. Deploy a GPO on the domain that points file servers at this
   collector (see ``get_gpo_config()``).

After that, events flow automatically.  The ``WEFProvider`` reads
from the local "ForwardedEvents" log — no polling of remote machines.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
import textwrap
from dataclasses import dataclass
from xml.sax.saxutils import escape as xml_escape

logger = logging.getLogger(__name__)

_SUBSCRIPTION_NAME = "OpenLabels-FileAccess"


@dataclass
class WEFSubscriptionInfo:
    """Status of a WEF subscription."""

    name: str
    enabled: bool
    source_count: int
    delivery_mode: str
    status: str
    error: str | None = None


def _run_wecutil(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a wecutil command synchronously."""
    cmd = ["wecutil", *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


async def init_collector() -> tuple[bool, str]:
    """Initialize the Windows Event Collector service.

    Equivalent to ``wecutil qc /q:true`` — enables and starts the
    Windows Event Collector service if not already running.

    Returns (success, message).
    """
    try:
        proc = await asyncio.to_thread(_run_wecutil, "qc", "/q:true")
        if proc.returncode == 0:
            return True, "Event Collector service initialized"
        return False, proc.stderr.strip() or f"wecutil qc exited {proc.returncode}"
    except FileNotFoundError:
        return False, "wecutil not found — WEF requires Windows Server"
    except Exception as e:
        return False, str(e)


def _build_subscription_xml(
    subscription_name: str = _SUBSCRIPTION_NAME,
    event_ids: list[int] | None = None,
    delivery_max_items: int = 10,
    delivery_max_latency_ms: int = 60_000,
    transport: str = "HTTP",
    allowed_sddl: str = "O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)",
) -> str:
    """Build the XML config for a source-initiated WEF subscription.

    The default SDDL allows Domain Computers (DC) and Network Service
    (NS) to push events.  Adjust if you need to restrict to a specific
    security group.
    """
    if event_ids is None:
        event_ids = [4663, 4656]

    # Validate transport to prevent unexpected values in the XML
    transport = transport.upper()
    if transport not in ("HTTP", "HTTPS"):
        raise ValueError(f"transport must be 'HTTP' or 'HTTPS', got {transport!r}")

    # Validate subscription name: only allow safe characters
    if not re.match(r'^[\w\-]+$', subscription_name):
        raise ValueError(
            "subscription_name must contain only alphanumeric characters, "
            "hyphens, and underscores"
        )

    id_filter = " or ".join(f"EventID={eid}" for eid in event_ids)
    safe_name = xml_escape(subscription_name)

    return textwrap.dedent(f"""\
        <Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
            <SubscriptionId>{safe_name}</SubscriptionId>
            <SubscriptionType>SourceInitiated</SubscriptionType>
            <Description>{xml_escape(f"OpenLabels file access event collection (Events {', '.join(str(e) for e in event_ids)})")}</Description>
            <Enabled>true</Enabled>
            <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
            <ConfigurationMode>Custom</ConfigurationMode>
            <Delivery Mode="Push">
                <Batching>
                    <MaxItems>{delivery_max_items}</MaxItems>
                    <MaxLatencyTime>{delivery_max_latency_ms}</MaxLatencyTime>
                </Batching>
            </Delivery>
            <Query>
                <![CDATA[
                    <QueryList>
                        <Query Id="0" Path="Security">
                            <Select Path="Security">*[System[({id_filter})]]</Select>
                        </Query>
                    </QueryList>
                ]]>
            </Query>
            <ReadExistingEvents>false</ReadExistingEvents>
            <TransportName>{transport}</TransportName>
            <ContentFormat>Events</ContentFormat>
            <Locale Language="en-US"/>
            <LogFile>ForwardedEvents</LogFile>
            <AllowedSourceNonDomainComputers/>
            <AllowedSourceDomainComputers>{xml_escape(allowed_sddl)}</AllowedSourceDomainComputers>
        </Subscription>""")


async def create_subscription(
    subscription_name: str = _SUBSCRIPTION_NAME,
    event_ids: list[int] | None = None,
    transport: str = "HTTP",
) -> tuple[bool, str]:
    """Create (or update) the WEF subscription on this collector.

    Writes the subscription XML to a temp file and runs
    ``wecutil cs <file>`` to register it.

    Returns (success, message).
    """
    import tempfile
    from pathlib import Path

    xml = _build_subscription_xml(
        subscription_name=subscription_name,
        event_ids=event_ids,
        transport=transport,
    )

    try:
        # Write XML to temp file (wecutil reads from file, not stdin)
        tmp = Path(tempfile.gettempdir()) / f"openlabels-wef-{subscription_name}.xml"
        tmp.write_text(xml, encoding="utf-8")

        # Check if subscription already exists
        check = await asyncio.to_thread(_run_wecutil, "gs", subscription_name)
        if check.returncode == 0:
            # Update existing
            proc = await asyncio.to_thread(
                _run_wecutil, "ss", subscription_name, f"/c:{tmp}",
            )
        else:
            # Create new
            proc = await asyncio.to_thread(_run_wecutil, "cs", str(tmp))

        tmp.unlink(missing_ok=True)

        if proc.returncode == 0:
            logger.info("WEF subscription '%s' created/updated", subscription_name)
            return True, f"Subscription '{subscription_name}' active"
        return False, proc.stderr.strip() or f"wecutil exited {proc.returncode}"

    except FileNotFoundError:
        return False, "wecutil not found — WEF requires Windows Server"
    except Exception as e:
        logger.warning("Failed to create WEF subscription: %s", e)
        return False, str(e)


async def delete_subscription(
    subscription_name: str = _SUBSCRIPTION_NAME,
) -> tuple[bool, str]:
    """Delete a WEF subscription."""
    try:
        proc = await asyncio.to_thread(_run_wecutil, "ds", subscription_name)
        if proc.returncode == 0:
            return True, f"Subscription '{subscription_name}' deleted"
        return False, proc.stderr.strip() or f"wecutil ds exited {proc.returncode}"
    except FileNotFoundError:
        return False, "wecutil not found"
    except Exception as e:
        return False, str(e)


async def get_subscription_status(
    subscription_name: str = _SUBSCRIPTION_NAME,
) -> WEFSubscriptionInfo:
    """Get the runtime status of a WEF subscription."""
    try:
        proc = await asyncio.to_thread(
            _run_wecutil, "gs", subscription_name, "/f:xml",
        )
        if proc.returncode != 0:
            return WEFSubscriptionInfo(
                name=subscription_name,
                enabled=False,
                source_count=0,
                delivery_mode="",
                status="not_found",
                error=proc.stderr.strip() or "Subscription not found",
            )

        # Parse key fields from wecutil XML output using proper XML parser
        output = proc.stdout
        try:
            try:
                import defusedxml.ElementTree as ET
            except ImportError:
                import xml.etree.ElementTree as ET  # noqa: S405

            root = ET.fromstring(output)
            # Handle namespaced and non-namespaced XML
            ns = {"s": "http://schemas.microsoft.com/2006/03/windows/events/subscription"}

            # Try namespaced first, fall back to non-namespaced
            enabled_el = root.find(".//s:Enabled", ns) or root.find(".//Enabled")
            enabled = (
                enabled_el is not None
                and enabled_el.text is not None
                and enabled_el.text.strip().lower() == "true"
            )

            # Count source entries
            source_count = (
                len(root.findall(".//s:EventSource", ns))
                or len(root.findall(".//EventSource"))
            )

            # Determine status from runtime info
            status_el = root.find(".//s:RuntimeStatus", ns) or root.find(".//RuntimeStatus")
            if status_el is not None and status_el.text:
                raw_status = status_el.text.strip().lower()
                if "active" in raw_status:
                    status = "active"
                elif "inactive" in raw_status:
                    status = "inactive"
                else:
                    status = "active" if enabled else "disabled"
            else:
                status = "active" if enabled else "disabled"

        except ET.ParseError:
            # Fallback to string matching if XML parsing fails
            # (e.g., wecutil returned non-XML text output)
            enabled = "Enabled: true" in output or "enabled>true" in output.lower()
            source_count = output.count("<EventSource>") or output.count("EventSource")
            if "Active" in output:
                status = "active"
            elif "Inactive" in output:
                status = "inactive"
            else:
                status = "active" if enabled else "disabled"

        return WEFSubscriptionInfo(
            name=subscription_name,
            enabled=enabled,
            source_count=source_count,
            delivery_mode="Push",
            status=status,
        )

    except FileNotFoundError:
        return WEFSubscriptionInfo(
            name=subscription_name,
            enabled=False,
            source_count=0,
            delivery_mode="",
            status="error",
            error="wecutil not found — WEF requires Windows",
        )
    except Exception as e:
        return WEFSubscriptionInfo(
            name=subscription_name,
            enabled=False,
            source_count=0,
            delivery_mode="",
            status="error",
            error=str(e),
        )


async def list_subscriptions() -> list[str]:
    """List all WEF subscription names on this collector."""
    try:
        proc = await asyncio.to_thread(_run_wecutil, "es")
        if proc.returncode != 0:
            return []
        return [s.strip() for s in proc.stdout.strip().splitlines() if s.strip()]
    except (FileNotFoundError, Exception):
        return []


def get_gpo_config(
    collector_fqdn: str,
    use_https: bool = False,
    refresh_seconds: int = 60,
) -> str:
    """Generate the GPO configuration string for target file servers.

    This value goes into:
    Computer Configuration → Policies → Administrative Templates →
    Windows Components → Event Forwarding → Configure target
    Subscription Manager

    Returns the "Server=" string to paste into the GPO.
    """
    if use_https:
        return (
            f"Server=HTTPS://{collector_fqdn}:5986/wsman/SubscriptionManager/WEC,"
            f"Refresh={refresh_seconds}"
        )
    return (
        f"Server=http://{collector_fqdn}:5985/wsman/SubscriptionManager/WEC,"
        f"Refresh={refresh_seconds}"
    )
