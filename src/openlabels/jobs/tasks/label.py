"""
Label application task implementation.

Applies sensitivity labels to files using:
1. MIP SDK for local files (Windows + .NET required)
2. Microsoft Graph API for SharePoint/OneDrive files
3. Metadata/sidecar fallback for other scenarios

Security: Uses defusedxml to prevent XXE (XML External Entity) attacks
when parsing Office document XML content.
"""

import asyncio
import base64
import json
import logging
import shutil
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Optional, Dict, Tuple
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import ScanResult, SensitivityLabel

logger = logging.getLogger(__name__)

# Security: Use defusedxml to prevent XXE attacks
# defusedxml is a drop-in replacement that disables external entity processing
# Import standard library Element for type hints (defusedxml doesn't export it)
import xml.etree.ElementTree as _stdlib_ET

try:
    import defusedxml.ElementTree as ET
    _USING_DEFUSED_XML = True
except ImportError:
    # Fallback to standard library with manual XXE protection
    ET = _stdlib_ET
    _USING_DEFUSED_XML = False
    logger.warning(
        "defusedxml not installed - using standard xml.etree.ElementTree. "
        "For better XXE protection, install defusedxml: pip install defusedxml"
    )


def _safe_xml_fromstring(content: bytes) -> _stdlib_ET.Element:
    """
    Safely parse XML content with XXE protection.

    Security: When defusedxml is not available, this function provides
    basic XXE mitigation by checking for DOCTYPE declarations.

    Args:
        content: XML content as bytes

    Returns:
        Parsed XML Element

    Raises:
        ValueError: If suspicious XML content is detected
    """
    if _USING_DEFUSED_XML:
        # defusedxml handles XXE protection automatically
        return ET.fromstring(content)

    # Manual XXE check for standard library fallback
    # Check for DOCTYPE declarations which could enable XXE
    content_str = content.decode('utf-8', errors='ignore')[:1000].lower()
    if '<!doctype' in content_str or '<!entity' in content_str:
        logger.warning("Blocked potential XXE attack: DOCTYPE/ENTITY declaration detected")
        raise ValueError("XML content contains potentially unsafe DOCTYPE declaration")

    return ET.fromstring(content)

# Check for optional dependencies
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


async def execute_label_task(
    session: AsyncSession,
    payload: dict,
) -> dict:
    """
    Execute a label application task.

    Args:
        session: Database session
        payload: Task payload containing result_id and label_id

    Returns:
        Result dictionary with success status and details
    """
    result_id = UUID(payload["result_id"])
    label_id = payload["label_id"]  # Keep as string - SensitivityLabel uses string IDs from M365

    # Get scan result
    result = await session.get(ScanResult, result_id)
    if not result:
        raise ValueError(f"Result not found: {result_id}")

    # Get label
    label = await session.get(SensitivityLabel, label_id)
    if not label:
        raise ValueError(f"Label not found: {label_id}")

    logger.info(f"Applying label '{label.name}' to {result.file_path}")

    try:
        # Apply label based on file location
        labeling_result = await _apply_label(result, label)

        if labeling_result["success"]:
            result.label_applied = True
            result.label_applied_at = datetime.now(timezone.utc)
            result.current_label_id = label_id
            result.current_label_name = label.name
            result.label_error = None

            return {
                "success": True,
                "file_path": result.file_path,
                "label_id": label_id,
                "label_name": label.name,
                "method": labeling_result.get("method", "unknown"),
            }
        else:
            result.label_error = labeling_result.get("error", "Label application failed")
            return {
                "success": False,
                "file_path": result.file_path,
                "error": result.label_error,
                "method": labeling_result.get("method", "unknown"),
            }

    except (SQLAlchemyError, OSError, RuntimeError, ConnectionError) as e:
        logger.error(f"Failed to apply label: {e}")
        result.label_error = str(e)
        raise


async def _apply_label(result: ScanResult, label: SensitivityLabel) -> dict:
    """
    Apply a sensitivity label to a file.

    Routes to appropriate labeling method based on file location.
    """
    file_path = result.file_path

    # SharePoint/OneDrive URLs - use Graph API
    if file_path.startswith("https://") and ("sharepoint.com" in file_path or "onedrive" in file_path):
        return await _apply_label_graph(result, label)

    # Other HTTP URLs - cannot label
    if file_path.startswith("http"):
        return {
            "success": False,
            "method": "unsupported",
            "error": "Cannot apply labels to non-Microsoft cloud files",
        }

    # Local files - try MIP SDK, fall back to metadata
    return await _apply_label_local(result, label)


async def _apply_label_local(result: ScanResult, label: SensitivityLabel) -> dict:
    """
    Apply label to local files.

    Tries MIP SDK first, falls back to metadata if MIP unavailable.
    """
    file_path = result.file_path

    # Check if file exists
    if not Path(file_path).exists():
        return {
            "success": False,
            "method": "local",
            "error": f"File not found: {file_path}",
        }

    # Try MIP SDK first (Windows only, requires .NET)
    mip_result = await _apply_label_mip(file_path, label)
    if mip_result["success"]:
        return mip_result

    # If MIP not available/failed, try metadata approach
    if "not available" in mip_result.get("error", "").lower():
        metadata_result = await _apply_label_metadata(file_path, label)
        return metadata_result

    # MIP was available but failed - return MIP error
    return mip_result


async def _apply_label_mip(file_path: str, label: SensitivityLabel) -> dict:
    """
    Apply label using Microsoft Information Protection SDK.

    Requires Windows with .NET and the MIP SDK installed.
    """
    try:
        from openlabels.labeling.mip import MIPClient, is_mip_available

        if not is_mip_available():
            return {
                "success": False,
                "method": "mip",
                "error": "MIP SDK not available (pythonnet not installed)",
            }

        # Get MIP credentials from settings
        try:
            from openlabels.server.config import get_settings
            settings = get_settings()
            mip_config = getattr(settings, "mip", None)
        except (ImportError, RuntimeError, AttributeError) as e:
            logger.debug(f"Failed to get MIP config: {e}")
            mip_config = None

        if not mip_config:
            return {
                "success": False,
                "method": "mip",
                "error": "MIP SDK not available (not configured)",
            }

        # Initialize MIP client
        client = MIPClient(
            client_id=mip_config.client_id,
            client_secret=mip_config.client_secret,
            tenant_id=mip_config.tenant_id,
        )

        initialized = await client.initialize()
        if not initialized:
            return {
                "success": False,
                "method": "mip",
                "error": "MIP SDK not available (initialization failed)",
            }

        try:
            # Apply the label
            result = await client.apply_label(
                file_path=file_path,
                label_id=label.id,
                justification="Auto-labeled by OpenLabels based on content classification",
            )

            return {
                "success": result.success,
                "method": "mip",
                "error": result.error if not result.success else None,
            }
        finally:
            await client.shutdown()

    except ImportError:
        return {
            "success": False,
            "method": "mip",
            "error": "MIP SDK not available (module not found)",
        }
    except (RuntimeError, OSError, ValueError) as e:
        logger.error(f"MIP SDK error: {e}")
        return {
            "success": False,
            "method": "mip",
            "error": str(e),
        }


async def _apply_label_metadata(file_path: str, label: SensitivityLabel) -> dict:
    """
    Apply label using file metadata (custom properties).

    This is a fallback when MIP SDK is not available. It stores label
    information in file metadata but does NOT provide MIP encryption
    or protection features.
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    # For Office documents, add custom properties
    if ext in (".docx", ".xlsx", ".pptx"):
        return await _apply_label_office_metadata(file_path, label)

    # For PDFs, add metadata
    if ext == ".pdf":
        return await _apply_label_pdf_metadata(file_path, label)

    # For other files, create a sidecar file
    return await _apply_label_sidecar(file_path, label)


async def _apply_label_office_metadata(file_path: str, label: SensitivityLabel) -> dict:
    """Add label to Office document custom properties."""
    try:
        path = Path(file_path)
        temp_path = path.with_suffix(path.suffix + ".tmp")

        # Read and modify the document
        with zipfile.ZipFile(file_path, "r") as zf_in:
            with zipfile.ZipFile(temp_path, "w", zipfile.ZIP_DEFLATED) as zf_out:
                has_custom = "docProps/custom.xml" in zf_in.namelist()

                for item in zf_in.namelist():
                    content = zf_in.read(item)

                    # Update custom properties if exists
                    if item == "docProps/custom.xml":
                        content = _update_custom_props_xml(content, label)
                    # Update content types if we need to add custom props
                    elif item == "[Content_Types].xml" and not has_custom:
                        content = _update_content_types(content)

                    zf_out.writestr(item, content)

                # Add custom properties if they don't exist
                if not has_custom:
                    custom_xml = _create_custom_props_xml(label)
                    zf_out.writestr("docProps/custom.xml", custom_xml)

                    # Also need to update _rels/.rels
                    if "docProps/_rels/core.xml.rels" not in zf_in.namelist():
                        pass  # Custom props don't need explicit relationship

        # Replace original with modified
        shutil.move(str(temp_path), file_path)

        logger.info(f"Applied label via Office metadata: {file_path}")
        return {
            "success": True,
            "method": "office_metadata",
        }

    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as e:
        logger.error(f"Office metadata labeling failed: {e}")
        # Clean up temp file if it exists
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError as cleanup_err:
            logger.debug(f"Failed to clean up temp file: {cleanup_err}")
        return {
            "success": False,
            "method": "office_metadata",
            "error": str(e),
        }


def _create_custom_props_xml(label: SensitivityLabel) -> bytes:
    """Create custom properties XML with label info."""
    ns_props = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
    ns_vt = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"

    xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="{ns_props}" xmlns:vt="{ns_vt}">
    <property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="2" name="OpenLabels_LabelId">
        <vt:lpwstr>{label.id}</vt:lpwstr>
    </property>
    <property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="3" name="OpenLabels_LabelName">
        <vt:lpwstr>{label.name}</vt:lpwstr>
    </property>
    <property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="4" name="Classification">
        <vt:lpwstr>{label.name}</vt:lpwstr>
    </property>
</Properties>"""
    return xml.encode("utf-8")


def _update_custom_props_xml(content: bytes, label: SensitivityLabel) -> bytes:
    """Update existing custom properties XML with label info."""
    try:
        ns = {
            "cp": "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties",
            "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
        }

        # Register namespaces to preserve them in output
        ET.register_namespace("", ns["cp"])
        ET.register_namespace("vt", ns["vt"])

        # Security: Use safe XML parsing to prevent XXE attacks
        root = _safe_xml_fromstring(content)

        label_props = {
            "OpenLabels_LabelId": label.id,
            "OpenLabels_LabelName": label.name,
            "Classification": label.name,
        }

        # Find max PID and update existing props
        max_pid = 1
        for prop in root.findall(".//{%s}property" % ns["cp"]):
            pid = int(prop.get("pid", "0"))
            if pid > max_pid:
                max_pid = pid

            name = prop.get("name")
            if name in label_props:
                vt_elem = prop.find("{%s}lpwstr" % ns["vt"])
                if vt_elem is not None:
                    vt_elem.text = label_props[name]
                del label_props[name]

        # Add missing properties
        for name, value in label_props.items():
            max_pid += 1
            prop = ET.SubElement(root, "{%s}property" % ns["cp"])
            prop.set("fmtid", "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}")
            prop.set("pid", str(max_pid))
            prop.set("name", name)
            vt = ET.SubElement(prop, "{%s}lpwstr" % ns["vt"])
            vt.text = value

        return ET.tostring(root, encoding="utf-8", xml_declaration=True)

    except (ValueError, OSError, KeyError) as e:
        logger.debug(f"Failed to update custom props XML, creating new: {e}")
        return _create_custom_props_xml(label)


def _update_content_types(content: bytes) -> bytes:
    """Update content types to include custom properties."""
    try:
        ns = "http://schemas.openxmlformats.org/package/2006/content-types"
        # Use stdlib for register_namespace (defusedxml doesn't have it)
        _stdlib_ET.register_namespace("", ns)

        # Security: Use safe XML parsing to prevent XXE attacks
        root = _safe_xml_fromstring(content)

        # Check if custom properties type already exists
        for override in root.findall(".//{%s}Override" % ns):
            if override.get("PartName") == "/docProps/custom.xml":
                return content

        # Add override for custom properties (use stdlib for modification)
        override = _stdlib_ET.SubElement(root, "{%s}Override" % ns)
        override.set("PartName", "/docProps/custom.xml")
        override.set("ContentType", "application/vnd.openxmlformats-officedocument.custom-properties+xml")

        return _stdlib_ET.tostring(root, encoding="utf-8", xml_declaration=True)

    except (ValueError, OSError, KeyError) as e:
        logger.debug(f"Failed to update content types: {e}")
        return content


async def _apply_label_pdf_metadata(file_path: str, label: SensitivityLabel) -> dict:
    """Add label to PDF metadata."""
    # Try pypdf/PyPDF2
    try:
        try:
            from pypdf import PdfReader, PdfWriter
        except ImportError:
            from PyPDF2 import PdfReader, PdfWriter

        reader = PdfReader(file_path)
        writer = PdfWriter()

        # Copy all pages
        for page in reader.pages:
            writer.add_page(page)

        # Add label metadata
        writer.add_metadata({
            "/OpenLabels_LabelId": label.id,
            "/OpenLabels_LabelName": label.name,
            "/Classification": label.name,
        })

        # Write to temp file then replace
        temp_path = Path(file_path).with_suffix(".pdf.tmp")
        with open(temp_path, "wb") as f:
            writer.write(f)

        shutil.move(str(temp_path), file_path)

        logger.info(f"Applied label via PDF metadata: {file_path}")
        return {
            "success": True,
            "method": "pdf_metadata",
        }

    except ImportError:
        logger.debug("No PDF library available, using sidecar")
        return await _apply_label_sidecar(file_path, label)
    except (OSError, RuntimeError, ValueError) as e:
        logger.error(f"PDF metadata labeling failed: {e}")
        return {
            "success": False,
            "method": "pdf_metadata",
            "error": str(e),
        }


async def _apply_label_sidecar(file_path: str, label: SensitivityLabel) -> dict:
    """Create a sidecar file with label information."""
    try:
        sidecar_path = Path(file_path).with_suffix(Path(file_path).suffix + ".openlabels")

        sidecar_data = {
            "file": str(file_path),
            "label_id": label.id,
            "label_name": label.name,
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "applied_by": "OpenLabels",
        }

        with open(sidecar_path, "w") as f:
            json.dump(sidecar_data, f, indent=2)

        logger.info(f"Applied label via sidecar: {sidecar_path}")
        return {
            "success": True,
            "method": "sidecar",
        }

    except (OSError, ValueError) as e:
        logger.error(f"Sidecar labeling failed: {e}")
        return {
            "success": False,
            "method": "sidecar",
            "error": str(e),
        }


async def _apply_label_graph(result: ScanResult, label: SensitivityLabel) -> dict:
    """
    Apply label using Microsoft Graph API.

    Works with SharePoint and OneDrive files.
    """
    if not HTTPX_AVAILABLE:
        return {
            "success": False,
            "method": "graph",
            "error": "httpx not installed (pip install httpx)",
        }

    try:
        from openlabels.server.config import get_settings
        settings = get_settings()

        graph_config = getattr(settings, "graph", None)
        if not graph_config:
            return {
                "success": False,
                "method": "graph",
                "error": "Graph API not configured in settings",
            }

        # Get access token
        token = await _get_graph_token(
            tenant_id=graph_config.tenant_id,
            client_id=graph_config.client_id,
            client_secret=graph_config.client_secret,
        )

        if not token:
            return {
                "success": False,
                "method": "graph",
                "error": "Failed to obtain Graph API access token",
            }

        # Parse the SharePoint/OneDrive URL to get site and item IDs
        file_url = result.file_path
        site_id, item_id = await _parse_sharepoint_url(file_url, token)

        if not site_id or not item_id:
            return {
                "success": False,
                "method": "graph",
                "error": "Could not resolve SharePoint file location from URL",
            }

        # Apply the label via Graph API
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/items/{item_id}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json={
                    "sensitivityLabel": {
                        "labelId": label.id,
                        "assignmentMethod": "standard",
                    }
                },
                timeout=30.0,
            )

            if response.status_code in (200, 204):
                logger.info(f"Applied label via Graph API: {file_url}")
                return {
                    "success": True,
                    "method": "graph",
                }
            else:
                error_msg = response.text[:500] if response.text else f"HTTP {response.status_code}"
                logger.error(f"Graph API error: {error_msg}")
                return {
                    "success": False,
                    "method": "graph",
                    "error": f"Graph API returned {response.status_code}",
                }

    except (ConnectionError, OSError, RuntimeError, ValueError) as e:
        logger.error(f"Graph API labeling failed: {e}")
        return {
            "success": False,
            "method": "graph",
            "error": str(e),
        }


async def _get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> Optional[str]:
    """Get OAuth2 access token for Microsoft Graph API."""
    if not HTTPX_AVAILABLE:
        return None

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
                timeout=30.0,
            )

            if response.status_code == 200:
                return response.json().get("access_token")
            else:
                logger.error(f"Failed to get Graph token: {response.status_code} - {response.text[:200]}")
                return None

    except (ConnectionError, OSError, RuntimeError, ValueError) as e:
        logger.error(f"Graph token error: {e}")
        return None


async def _parse_sharepoint_url(url: str, token: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse SharePoint/OneDrive URL to get site and item IDs.

    Uses the Graph API shares endpoint to resolve sharing URLs.
    """
    if not HTTPX_AVAILABLE:
        return None, None

    try:
        # Encode URL for shares endpoint
        encoded_url = "u!" + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://graph.microsoft.com/v1.0/shares/{encoded_url}/driveItem",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0,
            )

            if response.status_code == 200:
                data = response.json()
                parent_ref = data.get("parentReference", {})
                site_id = parent_ref.get("siteId")
                item_id = data.get("id")
                return site_id, item_id
            else:
                logger.debug(f"Could not resolve URL via shares endpoint: {response.status_code}")

    except (ConnectionError, OSError, RuntimeError, ValueError) as e:
        logger.error(f"Failed to parse SharePoint URL: {e}")

    return None, None
