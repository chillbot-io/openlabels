"""Tests for cursor-based pagination utilities."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from openlabels.server.pagination import (
    CursorData,
    CursorPaginationParams,
    decode_cursor,
    encode_cursor,
)


class TestEncodeDecode:
    """Tests for encode_cursor / decode_cursor roundtrip."""

    def test_roundtrip(self):
        id = uuid4()
        ts = datetime(2025, 6, 15, 12, 30, 0, tzinfo=timezone.utc)

        cursor = encode_cursor(id, ts)
        decoded = decode_cursor(cursor)

        assert decoded is not None
        assert decoded.id == id
        assert decoded.timestamp == ts

    def test_roundtrip_preserves_microseconds(self):
        id = uuid4()
        ts = datetime(2025, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)

        cursor = encode_cursor(id, ts)
        decoded = decode_cursor(cursor)

        assert decoded is not None
        assert decoded.timestamp == ts

    def test_encode_produces_url_safe_string(self):
        cursor = encode_cursor(uuid4(), datetime.now(timezone.utc))
        # URL-safe base64 should not contain +, /, or =
        assert "+" not in cursor
        assert "/" not in cursor


class TestDecodeCursor:
    """Tests for decode_cursor edge cases."""

    def test_empty_string_returns_none(self):
        assert decode_cursor("") is None

    def test_none_string_returns_none(self):
        assert decode_cursor(None) is None

    def test_garbage_returns_none(self):
        assert decode_cursor("not-a-valid-cursor!!!") is None

    def test_valid_base64_but_bad_json_returns_none(self):
        import base64
        bad = base64.urlsafe_b64encode(b"not json").decode()
        assert decode_cursor(bad) is None

    def test_missing_id_field_returns_none(self):
        import base64
        import json
        data = json.dumps({"ts": "2025-01-01T00:00:00+00:00"})
        cursor = base64.urlsafe_b64encode(data.encode()).decode()
        assert decode_cursor(cursor) is None

    def test_missing_ts_field_returns_none(self):
        import base64
        import json
        data = json.dumps({"id": str(uuid4())})
        cursor = base64.urlsafe_b64encode(data.encode()).decode()
        assert decode_cursor(cursor) is None

    def test_invalid_uuid_returns_none(self):
        import base64
        import json
        data = json.dumps({"id": "not-a-uuid", "ts": "2025-01-01T00:00:00+00:00"})
        cursor = base64.urlsafe_b64encode(data.encode()).decode()
        assert decode_cursor(cursor) is None


class TestCursorPaginationParams:
    """Tests for CursorPaginationParams validation."""

    def test_defaults(self):
        params = CursorPaginationParams()
        assert params.cursor is None
        assert params.limit == 50
        assert params.include_total is True

    def test_limit_bounds(self):
        params = CursorPaginationParams(limit=1)
        assert params.limit == 1

        params = CursorPaginationParams(limit=100)
        assert params.limit == 100

    def test_limit_below_minimum_rejected(self):
        with pytest.raises(Exception):  # Pydantic ValidationError
            CursorPaginationParams(limit=0)

    def test_limit_above_maximum_rejected(self):
        with pytest.raises(Exception):  # Pydantic ValidationError
            CursorPaginationParams(limit=101)

    def test_decode_with_valid_cursor(self):
        id = uuid4()
        ts = datetime(2025, 6, 1, tzinfo=timezone.utc)
        cursor_str = encode_cursor(id, ts)

        params = CursorPaginationParams(cursor=cursor_str)
        decoded = params.decode()

        assert decoded is not None
        assert decoded.id == id

    def test_decode_with_no_cursor(self):
        params = CursorPaginationParams()
        assert params.decode() is None
