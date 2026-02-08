"""
USN Journal provider for real-time NTFS change monitoring (Phase I).

Reads the Windows NTFS Update Sequence Number (USN) journal via
``ctypes`` / ``DeviceIoControl`` to capture file-level changes with
sub-second latency.

Dual-mode operation:
* **Batch** — ``collect(since)`` for backward-compatible harvester use.
* **Stream** — ``stream(shutdown_event)`` for ``EventStreamManager``.

Only available on Windows. On other platforms ``is_available()`` returns
``False`` and all collection methods return empty results.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
import struct
import sys
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Optional

from openlabels.monitoring.providers.base import RawAccessEvent

logger = logging.getLogger(__name__)

# ── USN reason-code → AccessAction mapping ───────────────────────────

# https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_DATA_TRUNCATION = 0x00000004
USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010
USN_REASON_NAMED_DATA_EXTEND = 0x00000020
USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_EA_CHANGE = 0x00000400
USN_REASON_SECURITY_CHANGE = 0x00000800
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_CLOSE = 0x80000000

_WRITE_REASONS = (
    USN_REASON_DATA_OVERWRITE
    | USN_REASON_DATA_EXTEND
    | USN_REASON_DATA_TRUNCATION
    | USN_REASON_NAMED_DATA_OVERWRITE
    | USN_REASON_NAMED_DATA_EXTEND
    | USN_REASON_NAMED_DATA_TRUNCATION
    | USN_REASON_FILE_CREATE
)
_DELETE_REASONS = USN_REASON_FILE_DELETE
_RENAME_REASONS = USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME
_PERMISSION_REASONS = USN_REASON_SECURITY_CHANGE


def _reason_to_action(reason: int) -> str:
    """Map a USN reason bitmask to an AccessAction string."""
    if reason & _DELETE_REASONS:
        return "delete"
    if reason & _RENAME_REASONS:
        return "rename"
    if reason & _PERMISSION_REASONS:
        return "permission_change"
    if reason & _WRITE_REASONS:
        return "write"
    return "write"  # Default for any other mutation


# ── Windows FILETIME → datetime ──────────────────────────────────────

_EPOCH_DIFF_100NS = 116_444_736_000_000_000  # 1601-01-01 → 1970-01-01


def _filetime_to_datetime(ft: int) -> datetime:
    """Convert a Windows FILETIME (100-ns ticks since 1601) to UTC datetime."""
    if ft <= 0:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    ts = (ft - _EPOCH_DIFF_100NS) / 10_000_000
    return datetime.fromtimestamp(ts, tz=timezone.utc)


# ── USN_RECORD_V2 parser ────────────────────────────────────────────

# Struct layout (fixed portion = 60 bytes for V2, then variable-length filename)
_USN_RECORD_V2_FIXED = struct.Struct("<IHHqqqIIIIHH")
#   RecordLength          I   4
#   MajorVersion          H   2
#   MinorVersion          H   2
#   FileReferenceNumber   q   8
#   ParentFileRefNumber   q   8
#   Usn                   q   8
#   TimeStamp             I+I 8 (FILETIME as two DWORDs — read as q below)
#   Reason                I   4
#   SourceInfo            I   4
#   SecurityId            I   4
#   FileAttributes        I   4
#   FileNameLength        H   2
#   FileNameOffset        H   2
# Total fixed = 64 bytes

_USN_RECORD_V2_FMT = "<IHHqqqQIIIIHH"
_USN_RECORD_V2_SIZE = struct.calcsize(_USN_RECORD_V2_FMT)  # 64


def parse_usn_records(buf: bytes) -> list[dict]:
    """Parse a buffer of packed USN_RECORD_V2 structures.

    Returns a list of dicts with keys: file_ref, parent_ref, usn,
    timestamp, reason, filename.
    """
    records: list[dict] = []
    offset = 0
    while offset + _USN_RECORD_V2_SIZE <= len(buf):
        (
            record_length,
            major_ver,
            _minor_ver,
            file_ref,
            parent_ref,
            usn,
            timestamp_ft,
            reason,
            _source_info,
            _security_id,
            _file_attrs,
            filename_length,
            filename_offset,
        ) = struct.unpack_from(_USN_RECORD_V2_FMT, buf, offset)

        if record_length == 0 or offset + record_length > len(buf):
            break

        if major_ver != 2:
            offset += record_length
            continue

        # Filename is UTF-16LE starting at (offset + filename_offset)
        fn_start = offset + filename_offset
        fn_end = fn_start + filename_length
        if fn_end <= len(buf):
            filename = buf[fn_start:fn_end].decode("utf-16-le", errors="replace")
        else:
            filename = ""

        records.append({
            "file_ref": file_ref,
            "parent_ref": parent_ref,
            "usn": usn,
            "timestamp": _filetime_to_datetime(timestamp_ft),
            "reason": reason,
            "filename": filename,
        })

        offset += record_length

    return records


# ── Windows API wrappers (ctypes) ────────────────────────────────────

_IS_WINDOWS = sys.platform == "win32"

# FSCTL codes
FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL = 0x000900BB
FSCTL_ENUM_USN_DATA = 0x000900B3

# READ_USN_JOURNAL_DATA_V0 struct (24 bytes)
_READ_USN_JOURNAL_DATA_V0 = struct.Struct("<qIIHH")
#   StartUsn         q  8
#   ReasonMask       I  4
#   ReturnOnlyOnClose I 4
#   Timeout          H  2 (actually DWORDLONG=8, but simplified)
#   BytesToWaitFor   H  2
# Pad to 24 bytes — use full struct below

_READ_JOURNAL_FMT = "<qIIQQ"
_READ_JOURNAL_SIZE = struct.calcsize(_READ_JOURNAL_FMT)  # 32


def _open_volume(drive_letter: str) -> int:
    """Open a volume handle for DeviceIoControl. Returns handle or -1."""
    if not _IS_WINDOWS:
        return -1

    kernel32 = ctypes.windll.kernel32
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3

    volume_path = f"\\\\.\\{drive_letter}:"
    handle = kernel32.CreateFileW(
        volume_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    return handle


def _close_handle(handle: int) -> None:
    """Close a Windows handle."""
    if _IS_WINDOWS and handle not in (-1, 0):
        ctypes.windll.kernel32.CloseHandle(handle)


def _query_usn_journal(handle: int) -> dict | None:
    """Query USN journal metadata (journal ID, first/next USN)."""
    if not _IS_WINDOWS:
        return None

    kernel32 = ctypes.windll.kernel32
    # USN_JOURNAL_DATA_V0: UsnJournalID(Q), FirstUsn(q), NextUsn(q),
    #   LowestValidUsn(q), MaxUsn(q), MaximumSize(Q), AllocationDelta(Q)
    buf = ctypes.create_string_buffer(64)
    bytes_returned = wintypes.DWORD(0)

    ok = kernel32.DeviceIoControl(
        handle,
        FSCTL_QUERY_USN_JOURNAL,
        None, 0,
        buf, 64,
        ctypes.byref(bytes_returned),
        None,
    )
    if not ok:
        return None

    journal_id, first_usn, next_usn = struct.unpack_from("<Qqq", buf.raw)
    return {
        "journal_id": journal_id,
        "first_usn": first_usn,
        "next_usn": next_usn,
    }


def _read_usn_journal(
    handle: int,
    start_usn: int,
    reason_mask: int = 0xFFFFFFFF,
    buffer_size: int = 65536,
) -> tuple[bytes, int]:
    """Read USN records starting at *start_usn*.

    Returns ``(data_bytes, next_usn)`` — *data_bytes* contains packed
    USN_RECORD_V2 structures; *next_usn* is the value to pass on the
    next call for incremental reads.
    """
    if not _IS_WINDOWS:
        return b"", start_usn

    kernel32 = ctypes.windll.kernel32

    # Pack READ_USN_JOURNAL_DATA_V0
    in_buf = struct.pack(
        _READ_JOURNAL_FMT,
        start_usn,       # StartUsn
        reason_mask,     # ReasonMask
        0,               # ReturnOnlyOnClose
        0,               # Timeout
        0,               # BytesToWaitFor
    )

    out_buf = ctypes.create_string_buffer(buffer_size)
    bytes_returned = wintypes.DWORD(0)

    ok = kernel32.DeviceIoControl(
        handle,
        FSCTL_READ_USN_JOURNAL,
        in_buf, len(in_buf),
        out_buf, buffer_size,
        ctypes.byref(bytes_returned),
        None,
    )
    if not ok:
        return b"", start_usn

    total = bytes_returned.value
    if total < 8:
        return b"", start_usn

    # First 8 bytes of output = next USN
    next_usn = struct.unpack_from("<q", out_buf.raw, 0)[0]
    data = out_buf.raw[8:total]
    return data, next_usn


# ── MFT reference → full path resolution ─────────────────────────────

def _resolve_path_via_mft(
    handle: int,
    parent_ref: int,
    filename: str,
    drive_letter: str,
) -> str:
    """Best-effort path resolution for a USN record.

    Falls back to ``<drive>:\\<filename>`` if parent traversal fails.
    """
    # Full MFT parent traversal requires repeated FSCTL_READ_FILE_USN_DATA
    # calls.  For now, use the simple approach: drive + filename.
    # A production implementation would cache parent_ref → path mappings.
    return f"{drive_letter}:\\{filename}"


# ── USNJournalProvider ───────────────────────────────────────────────


class USNJournalProvider:
    """Real-time NTFS change stream via USN journal.

    Implements the ``EventProvider`` protocol for harvester compatibility
    and provides an async ``stream()`` method for ``EventStreamManager``.
    """

    def __init__(
        self,
        drive_letter: str = "C",
        watched_paths: list[str] | None = None,
        reason_mask: int = 0xFFFFFFFF,
    ) -> None:
        self._drive = drive_letter.upper().rstrip(":")
        self._watched_paths: set[str] | None = (
            {p.lower() for p in watched_paths} if watched_paths else None
        )
        self._reason_mask = reason_mask
        self._last_usn: int = 0
        self._journal_id: int | None = None

    @property
    def name(self) -> str:
        return "usn_journal"

    @staticmethod
    def is_available() -> bool:
        """Return True if running on Windows."""
        return _IS_WINDOWS

    def update_watched_paths(self, paths: list[str]) -> None:
        """Update the set of watched paths for filtering."""
        self._watched_paths = {p.lower() for p in paths} if paths else None

    # ── EventProvider protocol ───────────────────────────────────────

    async def collect(
        self, since: datetime | None = None,
    ) -> list[RawAccessEvent]:
        """Batch-collect USN events (harvester-compatible)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._collect_sync, since)

    def _collect_sync(
        self, since: datetime | None = None,
    ) -> list[RawAccessEvent]:
        """Synchronous USN journal read."""
        if not _IS_WINDOWS:
            return []

        handle = _open_volume(self._drive)
        if handle in (-1, 0):
            logger.warning("Failed to open volume %s:", self._drive)
            return []

        try:
            # Initialize journal cursor on first call
            if self._journal_id is None:
                info = _query_usn_journal(handle)
                if info is None:
                    logger.warning("USN journal not available on %s:", self._drive)
                    return []
                self._journal_id = info["journal_id"]
                if self._last_usn == 0:
                    # Start from current position (don't replay history)
                    self._last_usn = info["next_usn"]
                    return []

            data, next_usn = _read_usn_journal(
                handle, self._last_usn, self._reason_mask,
            )
            if not data:
                self._last_usn = next_usn
                return []

            raw_records = parse_usn_records(data)
            self._last_usn = next_usn

            events: list[RawAccessEvent] = []
            for rec in raw_records:
                # Skip CLOSE-only records (no actual data change)
                if rec["reason"] == USN_REASON_CLOSE:
                    continue

                # Time filter
                if since and rec["timestamp"] <= since:
                    continue

                file_path = _resolve_path_via_mft(
                    handle, rec["parent_ref"], rec["filename"], self._drive,
                )

                # Path filter
                if self._watched_paths and file_path.lower() not in self._watched_paths:
                    continue

                events.append(RawAccessEvent(
                    file_path=file_path,
                    event_time=rec["timestamp"],
                    action=_reason_to_action(rec["reason"]),
                    event_source="usn_journal",
                    raw={"usn": rec["usn"], "reason": rec["reason"]},
                ))

            return events

        except Exception:
            logger.warning("USN journal read failed", exc_info=True)
            return []
        finally:
            _close_handle(handle)

    # ── Streaming mode (for EventStreamManager) ──────────────────────

    async def stream(
        self,
        shutdown_event: asyncio.Event,
        poll_interval: float = 0.5,
    ) -> AsyncIterator[list[RawAccessEvent]]:
        """Yield batches of events as they arrive.

        Polls the USN journal every *poll_interval* seconds until
        *shutdown_event* is set.
        """
        loop = asyncio.get_running_loop()
        while not shutdown_event.is_set():
            try:
                events = await loop.run_in_executor(
                    None, self._collect_sync, None,
                )
                if events:
                    yield events
            except Exception:
                logger.warning("USN stream read failed", exc_info=True)

            try:
                await asyncio.wait_for(
                    shutdown_event.wait(), timeout=poll_interval,
                )
                break
            except asyncio.TimeoutError:
                pass
