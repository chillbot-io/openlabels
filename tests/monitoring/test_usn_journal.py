"""Tests for USN Journal provider (Phase I)."""

import struct
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from openlabels.monitoring.providers.usn_journal import (
    USNJournalProvider,
    USN_REASON_DATA_OVERWRITE,
    USN_REASON_FILE_CREATE,
    USN_REASON_FILE_DELETE,
    USN_REASON_RENAME_NEW_NAME,
    USN_REASON_SECURITY_CHANGE,
    USN_REASON_CLOSE,
    _reason_to_action,
    _filetime_to_datetime,
    _USN_RECORD_V2_FMT,
    parse_usn_records,
)


class TestReasonToAction:
    """Tests for USN reason code → action mapping."""

    def test_data_overwrite_is_write(self):
        assert _reason_to_action(USN_REASON_DATA_OVERWRITE) == "write"

    def test_file_create_is_write(self):
        assert _reason_to_action(USN_REASON_FILE_CREATE) == "write"

    def test_file_delete_is_delete(self):
        assert _reason_to_action(USN_REASON_FILE_DELETE) == "delete"

    def test_rename_is_rename(self):
        assert _reason_to_action(USN_REASON_RENAME_NEW_NAME) == "rename"

    def test_security_change_is_permission_change(self):
        assert _reason_to_action(USN_REASON_SECURITY_CHANGE) == "permission_change"

    def test_delete_takes_precedence_over_write(self):
        """When both delete and write flags are set, delete wins."""
        combined = USN_REASON_FILE_DELETE | USN_REASON_DATA_OVERWRITE
        assert _reason_to_action(combined) == "delete"

    def test_rename_takes_precedence_over_write(self):
        combined = USN_REASON_RENAME_NEW_NAME | USN_REASON_DATA_OVERWRITE
        assert _reason_to_action(combined) == "rename"

    def test_unknown_reason_defaults_to_write(self):
        assert _reason_to_action(0x00004000) == "write"


class TestFiletimeConversion:
    """Tests for Windows FILETIME → datetime conversion."""

    def test_epoch(self):
        """FILETIME for Unix epoch."""
        ft = 116_444_736_000_000_000
        dt = _filetime_to_datetime(ft)
        assert dt.year == 1970
        assert dt.month == 1
        assert dt.day == 1

    def test_zero_returns_epoch(self):
        dt = _filetime_to_datetime(0)
        assert dt.year == 1970

    def test_negative_returns_epoch(self):
        dt = _filetime_to_datetime(-1)
        assert dt.year == 1970

    def test_known_date(self):
        """2026-01-15 12:00:00 UTC in FILETIME."""
        # 2026-01-15 12:00:00 UTC → Unix timestamp 1768478400
        # FILETIME = (1768478400 * 10_000_000) + 116_444_736_000_000_000
        ts = 1768478400
        ft = (ts * 10_000_000) + 116_444_736_000_000_000
        dt = _filetime_to_datetime(ft)
        assert dt.year == 2026
        assert dt.month == 1
        assert dt.day == 15


class TestParseUsnRecords:
    """Tests for USN_RECORD_V2 buffer parsing."""

    def _make_record(
        self,
        filename: str = "test.txt",
        reason: int = USN_REASON_DATA_OVERWRITE,
        file_ref: int = 1234,
        parent_ref: int = 5678,
        usn: int = 100,
        timestamp_ft: int = 116_444_736_000_000_000,
    ) -> bytes:
        """Build a packed USN_RECORD_V2 binary."""
        filename_bytes = filename.encode("utf-16-le")
        filename_offset = struct.calcsize(_USN_RECORD_V2_FMT)
        record_length = filename_offset + len(filename_bytes)
        # Pad to 8-byte boundary
        padded_length = (record_length + 7) & ~7

        header = struct.pack(
            _USN_RECORD_V2_FMT,
            padded_length,     # RecordLength
            2,                 # MajorVersion
            0,                 # MinorVersion
            file_ref,          # FileReferenceNumber
            parent_ref,        # ParentFileReferenceNumber
            usn,               # Usn
            timestamp_ft,      # TimeStamp (FILETIME)
            reason,            # Reason
            0,                 # SourceInfo
            0,                 # SecurityId
            0x20,              # FileAttributes (ARCHIVE)
            len(filename_bytes),  # FileNameLength
            filename_offset,   # FileNameOffset
        )

        data = header + filename_bytes
        # Pad to alignment
        data += b"\x00" * (padded_length - len(data))
        return data

    def test_parse_single_record(self):
        buf = self._make_record(filename="document.docx", reason=USN_REASON_DATA_OVERWRITE)
        records = parse_usn_records(buf)
        assert len(records) == 1
        assert records[0]["filename"] == "document.docx"
        assert records[0]["reason"] == USN_REASON_DATA_OVERWRITE

    def test_parse_multiple_records(self):
        buf = (
            self._make_record(filename="a.txt", usn=1)
            + self._make_record(filename="b.txt", usn=2)
            + self._make_record(filename="c.txt", usn=3)
        )
        records = parse_usn_records(buf)
        assert len(records) == 3
        assert records[0]["filename"] == "a.txt"
        assert records[1]["filename"] == "b.txt"
        assert records[2]["filename"] == "c.txt"

    def test_parse_empty_buffer(self):
        assert parse_usn_records(b"") == []

    def test_parse_truncated_buffer(self):
        """Truncated buffer should return what was parseable."""
        full = self._make_record(filename="test.txt")
        truncated = full[:30]  # Less than header size
        assert parse_usn_records(truncated) == []

    def test_skips_non_v2_records(self):
        """Records with major_version != 2 should be skipped."""
        buf = self._make_record(filename="test.txt")
        # Corrupt the major version (bytes 4-5)
        buf_list = bytearray(buf)
        struct.pack_into("<H", buf_list, 4, 3)  # Set to V3
        records = parse_usn_records(bytes(buf_list))
        assert len(records) == 0

    def test_preserves_usn_and_refs(self):
        buf = self._make_record(file_ref=42, parent_ref=99, usn=500)
        records = parse_usn_records(buf)
        assert records[0]["file_ref"] == 42
        assert records[0]["parent_ref"] == 99
        assert records[0]["usn"] == 500


class TestUSNJournalProvider:
    """Tests for USNJournalProvider class."""

    def test_name(self):
        provider = USNJournalProvider(drive_letter="C")
        assert provider.name == "usn_journal"

    def test_not_available_on_linux(self):
        assert USNJournalProvider.is_available() is False

    def test_update_watched_paths(self):
        provider = USNJournalProvider()
        provider.update_watched_paths(["/test/a.txt", "/test/b.txt"])
        assert provider._watched_paths == {"/test/a.txt", "/test/b.txt"}

    def test_update_watched_paths_none_clears(self):
        provider = USNJournalProvider(watched_paths=["/test/a.txt"])
        provider.update_watched_paths([])
        assert provider._watched_paths is None

    @pytest.mark.asyncio
    async def test_collect_returns_empty_on_non_windows(self):
        provider = USNJournalProvider()
        events = await provider.collect()
        assert events == []

    @pytest.mark.asyncio
    async def test_collect_with_since_filter(self):
        provider = USNJournalProvider()
        since = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = await provider.collect(since=since)
        assert events == []

    def test_drive_letter_normalization(self):
        provider = USNJournalProvider(drive_letter="d:")
        assert provider._drive == "D"

    def test_watched_paths_lowercased(self):
        provider = USNJournalProvider(watched_paths=["C:\\Users\\Test.txt"])
        assert "c:\\users\\test.txt" in provider._watched_paths
