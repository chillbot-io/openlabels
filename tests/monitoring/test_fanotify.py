"""Tests for fanotify provider (Phase I)."""

import struct
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from openlabels.monitoring.providers.fanotify import (
    FanotifyProvider,
    FAN_MODIFY,
    FAN_CLOSE_WRITE,
    FAN_CREATE,
    FAN_DELETE,
    FAN_DELETE_SELF,
    FAN_MOVED_FROM,
    FAN_MOVED_TO,
    FAN_ACCESS,
    _mask_to_action,
    _resolve_pid_user,
    _FANOTIFY_EVENT_SIZE,
)


class TestMaskToAction:
    """Tests for fanotify event mask → action mapping."""

    def test_modify_is_write(self):
        assert _mask_to_action(FAN_MODIFY) == "write"

    def test_close_write_is_write(self):
        assert _mask_to_action(FAN_CLOSE_WRITE) == "write"

    def test_create_is_write(self):
        assert _mask_to_action(FAN_CREATE) == "write"

    def test_delete_is_delete(self):
        assert _mask_to_action(FAN_DELETE) == "delete"

    def test_delete_self_is_delete(self):
        assert _mask_to_action(FAN_DELETE_SELF) == "delete"

    def test_moved_from_is_rename(self):
        assert _mask_to_action(FAN_MOVED_FROM) == "rename"

    def test_moved_to_is_rename(self):
        assert _mask_to_action(FAN_MOVED_TO) == "rename"

    def test_access_is_read(self):
        assert _mask_to_action(FAN_ACCESS) == "read"

    def test_delete_takes_precedence_over_write(self):
        combined = FAN_DELETE | FAN_MODIFY
        assert _mask_to_action(combined) == "delete"

    def test_rename_takes_precedence_over_write(self):
        combined = FAN_MOVED_TO | FAN_MODIFY
        assert _mask_to_action(combined) == "rename"


class TestResolvePidUser:
    """Tests for PID → username resolution."""

    def test_nonexistent_pid_returns_none(self):
        result = _resolve_pid_user(999999999)
        assert result is None

    def test_pid_zero_returns_none(self):
        result = _resolve_pid_user(0)
        assert result is None

    def test_current_process_resolves(self):
        """Current process PID should resolve to a username."""
        import os
        result = _resolve_pid_user(os.getpid())
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0


class TestFanotifyProvider:
    """Tests for FanotifyProvider class."""

    def test_name(self):
        with patch("openlabels.monitoring.providers.fanotify._fanotify_init", return_value=-1):
            provider = FanotifyProvider.__new__(FanotifyProvider)
            provider._fan_fd = -1
            provider._marked_paths = set()
            provider._event_mask = FAN_MODIFY
        assert provider.name == "fanotify"

    def test_is_available_on_linux(self):
        assert FanotifyProvider.is_available() == (sys.platform == "linux")

    @pytest.mark.asyncio
    async def test_collect_returns_empty_when_no_fd(self):
        provider = FanotifyProvider.__new__(FanotifyProvider)
        provider._fan_fd = -1
        provider._marked_paths = set()
        provider._event_mask = FAN_MODIFY

        events = await provider.collect()
        assert events == []

    def test_update_watched_paths_adds_and_removes(self):
        provider = FanotifyProvider.__new__(FanotifyProvider)
        provider._fan_fd = -1
        provider._marked_paths = set()
        provider._event_mask = FAN_MODIFY

        # With fd=-1, marks won't actually succeed but tracking should work
        provider.update_watched_paths(["/a", "/b"])
        # Paths won't be in _marked_paths because fd=-1
        assert provider._marked_paths == set()

    def test_close_resets_state(self):
        provider = FanotifyProvider.__new__(FanotifyProvider)
        provider._fan_fd = -1
        provider._marked_paths = {"/test"}
        provider._event_mask = FAN_MODIFY

        provider.close()
        assert provider._fan_fd == -1
        assert provider._marked_paths == set()

    @pytest.mark.asyncio
    async def test_collect_with_since_filter(self):
        provider = FanotifyProvider.__new__(FanotifyProvider)
        provider._fan_fd = -1
        provider._marked_paths = set()
        provider._event_mask = FAN_MODIFY

        since = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = await provider.collect(since=since)
        assert events == []


class TestFanotifyEventParsing:
    """Tests for fanotify event metadata parsing."""

    def test_event_metadata_size(self):
        """fanotify_event_metadata should be 24 bytes on 64-bit."""
        assert _FANOTIFY_EVENT_SIZE == 24

    def test_mask_combinations(self):
        """Multiple event flags can be combined."""
        combined = FAN_CREATE | FAN_MODIFY | FAN_CLOSE_WRITE
        assert combined & FAN_CREATE
        assert combined & FAN_MODIFY
        assert combined & FAN_CLOSE_WRITE
        assert not (combined & FAN_DELETE)
