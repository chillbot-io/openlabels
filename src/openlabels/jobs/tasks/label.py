"""
Label application task implementation.

Thin task wrapper that delegates all labeling logic to
:class:`openlabels.labeling.engine.LabelingEngine`.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.adapters.base import FileInfo
from openlabels.labeling.engine import create_labeling_engine
from openlabels.server.models import ScanResult, SensitivityLabel

logger = logging.getLogger(__name__)


def _infer_adapter(file_path: str) -> str:
    """Infer the adapter type from a file path or URL."""
    if file_path.startswith("https://"):
        if "sharepoint.com" in file_path:
            return "sharepoint"
        if "onedrive" in file_path:
            return "onedrive"
    return "filesystem"


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
        # Build a FileInfo for the engine
        adapter = _infer_adapter(result.file_path)

        # Non-Microsoft HTTP URLs cannot be labeled
        if result.file_path.startswith("http") and adapter == "filesystem":
            return {
                "success": False,
                "file_path": result.file_path,
                "error": "Cannot apply labels to non-Microsoft cloud files",
                "method": "unsupported",
            }

        file_info = FileInfo.from_scan_result(result, adapter=adapter)

        engine = create_labeling_engine()

        labeling_result = await engine.apply_label(file_info, label_id, label.name)

        if labeling_result.success:
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
                "method": labeling_result.method or "unknown",
            }
        else:
            result.label_error = labeling_result.error or "Label application failed"
            return {
                "success": False,
                "file_path": result.file_path,
                "error": result.label_error,
                "method": labeling_result.method or "unknown",
            }

    except (SQLAlchemyError, OSError, RuntimeError, ConnectionError) as e:
        logger.error(f"Failed to apply label: {e}")
        result.label_error = str(e)
        raise
