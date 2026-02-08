"""Tests for Phase I change providers (USNChangeProvider, FanotifyChangeProvider)."""

import asyncio
from datetime import datetime, timezone

import pytest

from openlabels.core.change_providers import (
    USNChangeProvider,
    FanotifyChangeProvider,
    _StreamChangeProvider,
)


class TestStreamChangeProvider:
    """Tests for the base _StreamChangeProvider."""

    def test_notify_records_change(self):
        provider = _StreamChangeProvider()
        provider.notify("/test/file.txt")
        assert "/test/file.txt" in provider._changed

    def test_notify_multiple_files(self):
        provider = _StreamChangeProvider()
        provider.notify("/a.txt")
        provider.notify("/b.txt")
        assert len(provider._changed) == 2

    def test_notify_same_file_updates_timestamp(self):
        provider = _StreamChangeProvider()
        provider.notify("/a.txt")
        first_ts = provider._changed["/a.txt"]
        provider.notify("/a.txt")
        # Timestamp should be updated (or at least same)
        assert provider._changed["/a.txt"] >= first_ts

    @pytest.mark.asyncio
    async def test_changed_files_yields_notified(self):
        provider = _StreamChangeProvider()
        provider.notify("/test/file.txt")

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 1
        assert files[0].path == "/test/file.txt"
        assert files[0].name == "file.txt"

    @pytest.mark.asyncio
    async def test_changed_files_clears_after_yield(self):
        provider = _StreamChangeProvider()
        provider.notify("/test/file.txt")

        # First call yields the file
        files1 = []
        async for fi in provider.changed_files():
            files1.append(fi)
        assert len(files1) == 1

        # Second call should be empty
        files2 = []
        async for fi in provider.changed_files():
            files2.append(fi)
        assert len(files2) == 0

    @pytest.mark.asyncio
    async def test_changed_files_empty_when_no_changes(self):
        provider = _StreamChangeProvider()
        files = []
        async for fi in provider.changed_files():
            files.append(fi)
        assert len(files) == 0


class TestUSNChangeProvider:
    """Tests for USNChangeProvider."""

    def test_is_stream_change_provider(self):
        provider = USNChangeProvider()
        assert isinstance(provider, _StreamChangeProvider)

    @pytest.mark.asyncio
    async def test_usn_change_provider_works(self):
        provider = USNChangeProvider()
        provider.notify("C:\\Users\\doc.txt")

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 1
        assert files[0].path == "C:\\Users\\doc.txt"


class TestFanotifyChangeProvider:
    """Tests for FanotifyChangeProvider."""

    def test_is_stream_change_provider(self):
        provider = FanotifyChangeProvider()
        assert isinstance(provider, _StreamChangeProvider)

    @pytest.mark.asyncio
    async def test_fanotify_change_provider_works(self):
        provider = FanotifyChangeProvider()
        provider.notify("/home/user/secret.pdf")

        files = []
        async for fi in provider.changed_files():
            files.append(fi)

        assert len(files) == 1
        assert files[0].path == "/home/user/secret.pdf"
