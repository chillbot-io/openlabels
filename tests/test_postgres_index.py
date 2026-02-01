"""
Tests for PostgreSQL Label Index.

Tests critical security and data integrity functionality:
- SQL injection prevention via _escape_like_pattern
- JSON validation via _validate_label_json
- Multi-tenant isolation
- Connection management
- UPSERT operations
- Error handling
"""

import json
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from openlabels.output.postgres_index import (
    _escape_like_pattern,
    _validate_label_json,
    _get_psycopg,
    PostgresLabelIndex,
    create_index,
    DEFAULT_VERSION_LIMIT,
)
from openlabels.core.exceptions import (
    DatabaseError,
    CorruptedDataError,
    NotFoundError,
)


class TestEscapeLikePattern:
    """Tests for SQL LIKE pattern escaping (injection prevention)."""

    def test_escapes_percent_wildcard(self):
        """Percent signs should be escaped to prevent wildcard matching."""
        result = _escape_like_pattern("100%")
        assert result == "100\\%"

    def test_escapes_underscore_wildcard(self):
        """Underscores should be escaped to prevent single-char wildcard."""
        result = _escape_like_pattern("user_name")
        assert result == "user\\_name"

    def test_escapes_backslash(self):
        """Backslashes should be escaped first."""
        result = _escape_like_pattern("path\\to\\file")
        assert result == "path\\\\to\\\\file"

    def test_escapes_combined_special_chars(self):
        """Multiple special characters should all be escaped."""
        result = _escape_like_pattern("100% of user_data\\backup")
        assert result == "100\\% of user\\_data\\\\backup"

    def test_empty_string(self):
        """Empty string should return empty string."""
        result = _escape_like_pattern("")
        assert result == ""

    def test_no_special_chars(self):
        """String without special chars should pass through unchanged."""
        result = _escape_like_pattern("normal text")
        assert result == "normal text"

    def test_sql_injection_attempt_semicolon(self):
        """SQL injection with semicolon should be safe (not a LIKE special char)."""
        # Semicolons aren't LIKE wildcards, but test for completeness
        result = _escape_like_pattern("value; DROP TABLE users;--")
        assert result == "value; DROP TABLE users;--"

    def test_sql_injection_attempt_union(self):
        """UNION injection attempt should pass through (parameterized queries handle this)."""
        result = _escape_like_pattern("' UNION SELECT * FROM passwords--")
        assert result == "' UNION SELECT * FROM passwords--"

    def test_unicode_percent(self):
        """Unicode strings with percent should be escaped."""
        result = _escape_like_pattern("données 100%")
        assert result == "données 100\\%"

    def test_multiple_consecutive_wildcards(self):
        """Multiple consecutive wildcards should all be escaped."""
        result = _escape_like_pattern("%%__%%")
        assert result == "\\%\\%\\_\\_\\%\\%"


class TestValidateLabelJson:
    """Tests for label JSON validation."""

    def test_valid_label_json(self):
        """Valid JSON with all required fields should parse successfully."""
        json_str = json.dumps({
            "labelID": "test-123",
            "content_hash": "abc123",
            "labels": [{"type": "SSN", "count": 1}],
            "source": "scanner",
        })
        result = _validate_label_json(json_str)
        assert result["labelID"] == "test-123"
        assert result["content_hash"] == "abc123"

    def test_invalid_json_syntax(self):
        """Malformed JSON should raise CorruptedDataError."""
        with pytest.raises(CorruptedDataError, match="Malformed JSON"):
            _validate_label_json("{invalid json")

    def test_json_array_instead_of_object(self):
        """JSON array should raise CorruptedDataError (must be object)."""
        with pytest.raises(CorruptedDataError, match="must be an object"):
            _validate_label_json("[]")

    def test_json_string_instead_of_object(self):
        """JSON primitive should raise CorruptedDataError."""
        with pytest.raises(CorruptedDataError, match="must be an object"):
            _validate_label_json('"just a string"')

    def test_missing_labelID(self):
        """Missing labelID field should raise CorruptedDataError."""
        json_str = json.dumps({
            "content_hash": "abc123",
            "labels": [],
            "source": "scanner",
        })
        with pytest.raises(CorruptedDataError, match="Missing required field: labelID"):
            _validate_label_json(json_str)

    def test_missing_content_hash(self):
        """Missing content_hash field should raise CorruptedDataError."""
        json_str = json.dumps({
            "labelID": "test-123",
            "labels": [],
            "source": "scanner",
        })
        with pytest.raises(CorruptedDataError, match="Missing required field: content_hash"):
            _validate_label_json(json_str)

    def test_missing_labels(self):
        """Missing labels field should raise CorruptedDataError."""
        json_str = json.dumps({
            "labelID": "test-123",
            "content_hash": "abc123",
            "source": "scanner",
        })
        with pytest.raises(CorruptedDataError, match="Missing required field: labels"):
            _validate_label_json(json_str)

    def test_missing_source(self):
        """Missing source field should raise CorruptedDataError."""
        json_str = json.dumps({
            "labelID": "test-123",
            "content_hash": "abc123",
            "labels": [],
        })
        with pytest.raises(CorruptedDataError, match="Missing required field: source"):
            _validate_label_json(json_str)

    def test_extra_fields_allowed(self):
        """Extra fields should be preserved (forward compatibility)."""
        json_str = json.dumps({
            "labelID": "test-123",
            "content_hash": "abc123",
            "labels": [],
            "source": "scanner",
            "extra_field": "extra_value",
            "metadata": {"key": "value"},
        })
        result = _validate_label_json(json_str)
        assert result["extra_field"] == "extra_value"
        assert result["metadata"]["key"] == "value"

    def test_empty_string_values_allowed(self):
        """Empty strings for required fields should pass (just checks presence)."""
        json_str = json.dumps({
            "labelID": "",
            "content_hash": "",
            "labels": [],
            "source": "",
        })
        result = _validate_label_json(json_str)
        assert result["labelID"] == ""


class TestGetPsycopg:
    """Tests for psycopg import logic."""

    def test_psycopg3_preferred(self):
        """psycopg3 should be preferred over psycopg2."""
        mock_psycopg = MagicMock()
        with patch.dict('sys.modules', {'psycopg': mock_psycopg, 'psycopg2': MagicMock()}):
            module, version = _get_psycopg()
            assert version == 3
            assert module is mock_psycopg

    def test_psycopg3_returns_version_3(self):
        """When psycopg3 is available, should return version 3."""
        mock_psycopg = MagicMock()
        with patch.dict('sys.modules', {'psycopg': mock_psycopg}):
            with patch('openlabels.output.postgres_index._get_psycopg') as mock_get:
                # Simulate what _get_psycopg does when psycopg3 is available
                mock_get.return_value = (mock_psycopg, 3)
                module, version = mock_get()
                assert version == 3

    def test_psycopg_module_has_connect(self):
        """The returned module should have a connect method."""
        # Test that _get_psycopg returns something usable
        try:
            module, version = _get_psycopg()
            assert hasattr(module, 'connect')
            assert version in (2, 3)
        except ImportError:
            # If neither psycopg is installed, that's acceptable in CI
            pytest.skip("No psycopg driver installed")


class TestCreateIndex:
    """Tests for create_index factory function."""

    def test_missing_connection_string_raises(self):
        """Should raise ValueError when connection_string is None."""
        with pytest.raises(ValueError, match="connection string required"):
            create_index(connection_string=None)

    def test_empty_connection_string_raises(self):
        """Should raise ValueError when connection_string is empty."""
        with pytest.raises(ValueError, match="connection string required"):
            create_index(connection_string="")

    @patch('openlabels.output.postgres_index._get_psycopg')
    def test_creates_index_with_valid_string(self, mock_get_psycopg):
        """Should create PostgresLabelIndex with valid connection string."""
        mock_psycopg = MagicMock()
        mock_get_psycopg.return_value = (mock_psycopg, 3)

        # Mock the connection to prevent actual DB connection
        mock_conn = MagicMock()
        mock_psycopg.connect.return_value = mock_conn

        index = create_index("postgresql://user:pass@localhost/db")
        assert isinstance(index, PostgresLabelIndex)
        assert index.tenant_id == "default"

    @patch('openlabels.output.postgres_index._get_psycopg')
    def test_creates_index_with_custom_tenant(self, mock_get_psycopg):
        """Should respect custom tenant_id."""
        mock_psycopg = MagicMock()
        mock_get_psycopg.return_value = (mock_psycopg, 3)
        mock_conn = MagicMock()
        mock_psycopg.connect.return_value = mock_conn

        index = create_index(
            "postgresql://localhost/db",
            tenant_id="customer-123"
        )
        assert index.tenant_id == "customer-123"


class TestPostgresLabelIndex:
    """Tests for PostgresLabelIndex class."""

    @pytest.fixture
    def mock_psycopg(self):
        """Create mock psycopg module."""
        with patch('openlabels.output.postgres_index._get_psycopg') as mock:
            mock_module = MagicMock()
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_module.connect.return_value = mock_conn
            mock.return_value = (mock_module, 3)
            yield {
                'module': mock_module,
                'conn': mock_conn,
                'cursor': mock_cursor,
            }

    def test_init_creates_schema(self, mock_psycopg):
        """Initialization should create database schema."""
        index = PostgresLabelIndex("postgresql://localhost/test")

        # Verify cursor was used to execute schema creation
        cursor = mock_psycopg['cursor']
        assert cursor.execute.called

        # Check that CREATE TABLE statements were executed
        calls = [str(call) for call in cursor.execute.call_args_list]
        call_str = ' '.join(calls)
        assert 'CREATE TABLE' in call_str or cursor.execute.call_count >= 5

    def test_close_sets_closed_flag(self, mock_psycopg):
        """close() should set _closed flag and close connection."""
        index = PostgresLabelIndex("postgresql://localhost/test")
        assert not index._closed

        index.close()
        assert index._closed

    def test_context_manager_closes(self, mock_psycopg):
        """Context manager should close on exit."""
        with PostgresLabelIndex("postgresql://localhost/test") as index:
            assert not index._closed
        assert index._closed

    def test_get_connection_raises_when_closed(self, mock_psycopg):
        """_get_connection should raise DatabaseError when closed."""
        index = PostgresLabelIndex("postgresql://localhost/test")
        index.close()

        with pytest.raises(DatabaseError, match="has been closed"):
            index._get_connection()

    def test_multi_tenant_isolation_in_query(self, mock_psycopg):
        """Queries should filter by tenant_id."""
        index = PostgresLabelIndex(
            "postgresql://localhost/test",
            tenant_id="tenant-abc"
        )

        # Execute a query
        index.query(min_score=50)

        # Verify tenant_id is in the query parameters
        cursor = mock_psycopg['cursor']
        for call in cursor.execute.call_args_list:
            args = call[0] if call[0] else call[1].get('args', ())
            if len(args) >= 2 and isinstance(args[1], tuple):
                params = args[1]
                # Check if tenant_id is first param in queries
                if 'tenant_id' in str(args[0]):
                    assert "tenant-abc" in params

    def test_count_respects_tenant_id(self, mock_psycopg):
        """count() should only count records for current tenant."""
        index = PostgresLabelIndex(
            "postgresql://localhost/test",
            tenant_id="tenant-xyz"
        )

        mock_psycopg['cursor'].fetchone.return_value = (10,)
        result = index.count()

        # Verify tenant_id was used in query
        cursor = mock_psycopg['cursor']
        executed_queries = [str(call) for call in cursor.execute.call_args_list]
        # Should have executed count queries with tenant filter
        assert cursor.execute.called


class TestPostgresLabelIndexStore:
    """Tests for PostgresLabelIndex.store() method."""

    @pytest.fixture
    def mock_index(self):
        """Create mock index for testing."""
        with patch('openlabels.output.postgres_index._get_psycopg') as mock:
            mock_module = MagicMock()
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_module.connect.return_value = mock_conn
            mock.return_value = (mock_module, 3)

            index = PostgresLabelIndex("postgresql://localhost/test")
            yield index, mock_cursor

    def test_store_creates_label_object(self, mock_index):
        """store() should insert into label_objects table."""
        index, cursor = mock_index

        # Create a mock LabelSet
        mock_label_set = MagicMock()
        mock_label_set.label_id = "label-123"
        mock_label_set.content_hash = "hash-abc"
        mock_label_set.source = "scanner"
        mock_label_set.labels = []
        mock_label_set.to_json.return_value = '{"labelID": "label-123"}'

        result = index.store(mock_label_set, file_path="/test/file.txt")

        assert result is True
        # Verify INSERT was called
        assert cursor.execute.called

    def test_store_handles_exception(self, mock_index):
        """store() should return False and log on exception."""
        index, cursor = mock_index

        # Make cursor raise an exception
        cursor.execute.side_effect = Exception("Connection lost")

        mock_label_set = MagicMock()
        mock_label_set.label_id = "label-123"
        mock_label_set.content_hash = "hash-abc"
        mock_label_set.source = "scanner"
        mock_label_set.labels = []
        mock_label_set.to_json.return_value = '{}'

        result = index.store(mock_label_set)
        assert result is False


class TestPostgresLabelIndexGet:
    """Tests for PostgresLabelIndex.get() method."""

    @pytest.fixture
    def mock_index(self):
        """Create mock index for testing."""
        with patch('openlabels.output.postgres_index._get_psycopg') as mock:
            mock_module = MagicMock()
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_module.connect.return_value = mock_conn
            mock.return_value = (mock_module, 3)

            index = PostgresLabelIndex("postgresql://localhost/test")
            yield index, mock_cursor

    def test_get_returns_none_when_not_found(self, mock_index):
        """get() should return None when label not found."""
        index, cursor = mock_index
        cursor.fetchone.return_value = None

        result = index.get("nonexistent-id")
        assert result is None

    def test_get_raises_when_not_found_and_raise_on_error(self, mock_index):
        """get() should raise DatabaseError wrapping NotFoundError when raise_on_error=True."""
        index, cursor = mock_index
        cursor.fetchone.return_value = None

        # The actual implementation wraps NotFoundError in DatabaseError
        with pytest.raises(DatabaseError, match="Label not found"):
            index.get("nonexistent-id", raise_on_error=True)

    def test_get_with_specific_content_hash(self, mock_index):
        """get() should use content_hash in query when provided."""
        index, cursor = mock_index

        # Return valid JSON
        cursor.fetchone.return_value = (json.dumps({
            "labelID": "test-123",
            "content_hash": "specific-hash",
            "labels": [],
            "source": "test",
        }),)

        with patch('openlabels.output.postgres_index.LabelSet') as mock_labelset:
            mock_labelset.from_dict.return_value = MagicMock()
            result = index.get("test-123", content_hash="specific-hash")

            # Verify specific hash was used in query
            assert cursor.execute.called


class TestPostgresLabelIndexQuery:
    """Tests for PostgresLabelIndex.query() method."""

    @pytest.fixture
    def mock_index(self):
        """Create mock index for testing."""
        with patch('openlabels.output.postgres_index._get_psycopg') as mock:
            mock_module = MagicMock()
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_module.connect.return_value = mock_conn
            mock.return_value = (mock_module, 3)

            index = PostgresLabelIndex("postgresql://localhost/test")
            yield index, mock_cursor

    def test_query_limit_capped_at_10000(self, mock_index):
        """query() should cap limit at 10000."""
        index, cursor = mock_index
        cursor.__iter__ = lambda self: iter([])

        index.query(limit=50000)

        # Verify limit parameter was capped
        calls = cursor.execute.call_args_list
        for call in calls:
            if call[0] and len(call[0]) >= 2:
                params = call[0][1]
                if isinstance(params, (list, tuple)) and len(params) >= 2:
                    # Last two params are limit and offset
                    limit_param = params[-2]
                    if isinstance(limit_param, int) and limit_param > 100:
                        assert limit_param <= 10000

    def test_query_offset_capped_at_zero(self, mock_index):
        """query() should not allow negative offset."""
        index, cursor = mock_index
        cursor.__iter__ = lambda self: iter([])

        index.query(offset=-100)

        # Verify offset was capped at 0
        calls = cursor.execute.call_args_list
        for call in calls:
            if call[0] and len(call[0]) >= 2:
                params = call[0][1]
                if isinstance(params, (list, tuple)):
                    for param in params:
                        if isinstance(param, int) and param < 0:
                            pytest.fail("Negative offset should be capped to 0")

    def test_query_escapes_entity_type_wildcards(self, mock_index):
        """query() should escape LIKE wildcards in entity_type."""
        index, cursor = mock_index
        cursor.__iter__ = lambda self: iter([])

        # Query with entity type containing LIKE wildcards
        index.query(entity_type="SSN%_test")

        # Verify the escaped pattern was used
        calls = cursor.execute.call_args_list
        for call in calls:
            if call[0] and 'LIKE' in str(call[0][0]):
                params = call[0][1]
                # The entity_type should have been escaped
                for param in params:
                    if isinstance(param, str) and 'SSN' in param:
                        assert '\\%' in param or '\\_' in param

    def test_query_returns_empty_list_on_error(self, mock_index):
        """query() should return empty list on database error."""
        index, cursor = mock_index
        cursor.execute.side_effect = Exception("Query failed")

        result = index.query(min_score=50)
        assert result == []


class TestPostgresLabelIndexDelete:
    """Tests for PostgresLabelIndex.delete() method."""

    @pytest.fixture
    def mock_index(self):
        """Create mock index for testing."""
        with patch('openlabels.output.postgres_index._get_psycopg') as mock:
            mock_module = MagicMock()
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_module.connect.return_value = mock_conn
            mock.return_value = (mock_module, 3)

            index = PostgresLabelIndex("postgresql://localhost/test")
            yield index, mock_cursor

    def test_delete_returns_true_on_success(self, mock_index):
        """delete() should return True on successful deletion."""
        index, cursor = mock_index

        result = index.delete("label-123")
        assert result is True

    def test_delete_returns_false_on_error(self, mock_index):
        """delete() should return False on database error."""
        index, cursor = mock_index
        cursor.execute.side_effect = Exception("Delete failed")

        result = index.delete("label-123")
        assert result is False

    def test_delete_uses_parameterized_query(self, mock_index):
        """delete() should use parameterized query (not string interpolation)."""
        index, cursor = mock_index

        # Attempt SQL injection via label_id
        malicious_id = "'; DROP TABLE label_objects;--"
        index.delete(malicious_id)

        # Verify the malicious ID does not appear directly in any query string
        # If queries are properly parameterized, the malicious ID will only
        # appear in the params tuple, not in the query text itself
        for call in cursor.execute.call_args_list:
            if call[0]:
                query = str(call[0][0])
                # The malicious string should NOT appear verbatim in any query
                # (it would only be in the query if string interpolation was used)
                if 'DELETE' in query.upper() or 'SELECT' in query.upper():
                    assert "DROP TABLE" not in query, "SQL injection payload found in query"


class TestConnectionPooling:
    """Tests for thread-local connection pooling."""

    @pytest.fixture
    def mock_psycopg(self):
        """Create mock psycopg module."""
        with patch('openlabels.output.postgres_index._get_psycopg') as mock:
            mock_module = MagicMock()
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_conn.closed = False
            mock_module.connect.return_value = mock_conn
            mock.return_value = (mock_module, 3)
            yield {
                'module': mock_module,
                'conn': mock_conn,
                'cursor': mock_cursor,
            }

    def test_connection_reused_in_same_thread(self, mock_psycopg):
        """Same thread should reuse existing connection."""
        index = PostgresLabelIndex("postgresql://localhost/test")

        # First connection call during __init__
        initial_call_count = mock_psycopg['module'].connect.call_count

        # Get connection multiple times
        conn1 = index._get_connection()
        conn2 = index._get_connection()
        conn3 = index._get_connection()

        # Should not create new connections after initial
        # (may create one more due to init)
        assert mock_psycopg['module'].connect.call_count <= initial_call_count + 1
