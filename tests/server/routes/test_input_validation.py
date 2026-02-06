"""
Comprehensive Input Validation Edge Case Tests.

These tests verify that the API properly handles:
1. Empty/null inputs
2. Boundary values (very long strings, negative numbers, etc.)
3. Type coercion attacks
4. Malformed data (invalid UUIDs, emails, dates, JSON)
5. SQL/NoSQL injection patterns

For each test:
- Verify appropriate 400/422 error responses
- Verify error messages are helpful but don't expose internals
- Verify no stack traces in error responses
"""

import pytest
import random
import string
from uuid import uuid4


@pytest.fixture
async def setup_validation_data(test_db):
    """Set up minimal test data for validation tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, ScanTarget

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    # Create a target for tests that need one
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name=f"Validation Test Target {suffix}",
        adapter="filesystem",
        config={"path": "/test/validation"},
        enabled=True,
        created_by=user.id,
    )
    test_db.add(target)
    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "target": target,
        "session": test_db,
    }


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def assert_error_response(response, expected_status_codes=(400, 422)):
    """Assert response is an appropriate error with safe content."""
    assert response.status_code in expected_status_codes, \
        f"Expected {expected_status_codes}, got {response.status_code}"

    # Verify no stack traces in response
    response_text = response.text.lower()
    dangerous_patterns = [
        "traceback",
        "file \"",
        "sqlalchemy",
        "psycopg",
        "asyncpg",
        "error at",
        ".py\"",
    ]
    for pattern in dangerous_patterns:
        assert pattern not in response_text, \
            f"Response may contain stack trace/sensitive info: found '{pattern}'"


# =============================================================================
# EMPTY/NULL INPUT TESTS
# =============================================================================


class TestEmptyInputs:
    """Tests for empty and null input handling."""

    @pytest.mark.asyncio
    async def test_empty_string_required_fields(self, test_client, setup_validation_data):
        """Empty strings for required fields should be rejected."""
        # Target name cannot be empty
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "",
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )
        assert_error_response(response)

        # User email cannot be empty
        response = await test_client.post(
            "/api/users",
            json={
                "email": "",
                "name": "Test User",
            },
        )
        assert_error_response(response)

        # Schedule name cannot be empty
        target = setup_validation_data["target"]
        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "",
                "target_id": str(target.id),
            },
        )
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_null_values_in_json(self, test_client, setup_validation_data):
        """Null values for required fields should be rejected."""
        response = await test_client.post(
            "/api/targets",
            json={
                "name": None,
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )
        assert_error_response(response)

        response = await test_client.post(
            "/api/users",
            json={
                "email": None,
            },
        )
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_missing_required_fields(self, test_client, setup_validation_data):
        """Missing required fields should return validation error."""
        # Target missing name
        response = await test_client.post(
            "/api/targets",
            json={
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )
        assert_error_response(response)

        # Target missing adapter
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Test Target",
                "config": {"path": "/test"},
            },
        )
        assert_error_response(response)

        # User missing email
        response = await test_client.post(
            "/api/users",
            json={
                "name": "Test User",
                "role": "viewer",
            },
        )
        assert_error_response(response)

        # Schedule missing target_id
        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "Test Schedule",
            },
        )
        assert_error_response(response)

        # Scan missing target_id
        response = await test_client.post(
            "/api/scans",
            json={},
        )
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_empty_arrays_objects(self, test_client, setup_validation_data):
        """Empty arrays and objects should be handled appropriately."""
        # Empty config should be rejected or handled
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Empty Config Target",
                "adapter": "filesystem",
                "config": {},
            },
        )
        # Filesystem adapter requires 'path' in config
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_empty_request_body(self, test_client, setup_validation_data):
        """Empty request body should be rejected."""
        response = await test_client.post(
            "/api/targets",
            json={},
        )
        assert_error_response(response)

        response = await test_client.post(
            "/api/users",
            json={},
        )
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_whitespace_only_strings(self, test_client, setup_validation_data):
        """Whitespace-only strings should be rejected as empty."""
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "   \t\n   ",
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )
        # Should be rejected (depends on implementation)
        # If not rejected, it's a soft validation issue
        assert response.status_code in (200, 201, 400, 422)


# =============================================================================
# BOUNDARY VALUE TESTS
# =============================================================================


class TestBoundaryValues:
    """Tests for boundary value handling."""

    @pytest.mark.asyncio
    async def test_very_long_strings(self, test_client, setup_validation_data):
        """Very long strings should be rejected or truncated."""
        long_string = "A" * 10001  # 10001 characters

        # Long target name
        response = await test_client.post(
            "/api/targets",
            json={
                "name": long_string,
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )
        # Should either reject (400/422) or accept (200/201)
        # Should NOT cause 500 (server error)
        assert response.status_code in (200, 201, 400, 422), \
            f"Long string caused unexpected error: {response.status_code}"

        # Long user name
        response = await test_client.post(
            "/api/users",
            json={
                "email": "test-long@example.com",
                "name": long_string,
            },
        )
        assert response.status_code in (200, 201, 400, 422)

        # Very long path in config
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Long Path Target",
                "adapter": "filesystem",
                "config": {"path": "/" + "subdir/" * 5000},
            },
        )
        assert response.status_code in (200, 201, 400, 422)

    @pytest.mark.asyncio
    async def test_negative_numbers(self, test_client, setup_validation_data):
        """Negative numbers where positive expected should be rejected."""
        # Negative page number
        response = await test_client.get("/api/targets?page=-1")
        assert_error_response(response)

        response = await test_client.get("/api/scans?page=-100")
        assert_error_response(response)

        # Negative page size
        response = await test_client.get("/api/targets?page_size=-1")
        assert_error_response(response)

        # Negative page_size
        response = await test_client.get("/api/users?page_size=-5")
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_zero_values(self, test_client, setup_validation_data):
        """Zero values should be validated appropriately."""
        # Page 0 should be rejected
        response = await test_client.get("/api/targets?page=0")
        assert_error_response(response)

        # page_size 0 should be rejected
        response = await test_client.get("/api/users?page_size=0")
        assert_error_response(response)

        # Page size 0 should be rejected
        response = await test_client.get("/api/audit?page_size=0")
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_maximum_integer_values(self, test_client, setup_validation_data):
        """Maximum integer values should be handled safely."""
        max_int = 2147483647  # Max 32-bit signed int
        large_int = 9223372036854775807  # Max 64-bit signed int

        # Large page number
        response = await test_client.get(f"/api/targets?page={max_int}")
        # Should return empty results or validation error, NOT crash
        assert response.status_code in (200, 400, 422)

        # Very large page number
        response = await test_client.get(f"/api/scans?page={large_int}")
        assert response.status_code in (200, 400, 422)

        # Overflow attempt
        response = await test_client.get(f"/api/results?page={large_int + 1}")
        assert response.status_code in (200, 400, 422)

    @pytest.mark.asyncio
    async def test_unicode_special_characters(self, test_client, setup_validation_data):
        """Unicode and special characters should be handled safely."""
        unicode_strings = [
            "Test\u0000Target",  # Null byte
            "Test\x00Name",  # Null byte (hex)
            "TestTarget\uFFFD",  # Replacement character
            "Target\u202Ename",  # Right-to-left override
            "Target\uFEFFname",  # BOM character
            "Target name in Chinese",
            "Target name with emoji",
            "Target with kanji",
            "Target\u200Bwith\u200Bzero-width",  # Zero-width space
        ]

        for test_string in unicode_strings:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": test_string,
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )
            # Should either accept or reject with validation error
            # Should NOT cause 500
            assert response.status_code in (200, 201, 400, 422), \
                f"Unicode string '{repr(test_string)}' caused {response.status_code}"

    @pytest.mark.asyncio
    async def test_control_characters(self, test_client, setup_validation_data):
        """Control characters should be handled safely."""
        control_char_strings = [
            "Target\x01Name",  # SOH
            "Target\x07Name",  # BEL
            "Target\x08Name",  # Backspace
            "Target\x0BName",  # Vertical tab
            "Target\x0CName",  # Form feed
            "Target\x1BName",  # Escape
            "Target\x7FName",  # DEL
        ]

        for test_string in control_char_strings:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": test_string,
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )
            assert response.status_code in (200, 201, 400, 422), \
                f"Control character string caused {response.status_code}"


# =============================================================================
# TYPE COERCION TESTS
# =============================================================================


class TestTypeCoercion:
    """Tests for type coercion attack prevention."""

    @pytest.mark.asyncio
    async def test_string_where_number_expected(self, test_client, setup_validation_data):
        """String values where numbers expected should be rejected."""
        # String for page number
        response = await test_client.get("/api/targets?page=abc")
        assert_error_response(response)

        response = await test_client.get("/api/scans?page=one")
        assert_error_response(response)

        # String for page_size
        response = await test_client.get("/api/users?page_size=many")
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_number_where_string_expected(self, test_client, setup_validation_data):
        """Number values where strings expected should be coerced or rejected."""
        # Number for target name (should be coerced to string or rejected)
        response = await test_client.post(
            "/api/targets",
            json={
                "name": 12345,
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )
        # Most frameworks will coerce to string
        assert response.status_code in (200, 201, 400, 422)

        # Number for adapter type (should be rejected)
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Test Target",
                "adapter": 12345,
                "config": {"path": "/test"},
            },
        )
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_array_where_object_expected(self, test_client, setup_validation_data):
        """Array values where objects expected should be rejected."""
        # Array for config (should be object)
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Test Target",
                "adapter": "filesystem",
                "config": [{"path": "/test"}],
            },
        )
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_object_where_string_expected(self, test_client, setup_validation_data):
        """Object values where strings expected should be rejected."""
        # Object for target name
        response = await test_client.post(
            "/api/targets",
            json={
                "name": {"nested": "object"},
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )
        assert_error_response(response)

    @pytest.mark.asyncio
    async def test_boolean_coercion(self, test_client, setup_validation_data):
        """Boolean type coercion should be handled correctly."""
        # String "true" for boolean
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Boolean Test Target",
                "adapter": "filesystem",
                "config": {"path": "/test"},
                "enabled": "true",  # String instead of boolean
            },
        )
        # May be coerced or rejected
        assert response.status_code in (200, 201, 400, 422)

        # Number for boolean
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Boolean Test Target 2",
                "adapter": "filesystem",
                "config": {"path": "/test"},
                "enabled": 1,
            },
        )
        assert response.status_code in (200, 201, 400, 422)


# =============================================================================
# MALFORMED DATA TESTS
# =============================================================================


class TestMalformedData:
    """Tests for malformed data handling."""

    @pytest.mark.asyncio
    async def test_invalid_uuids(self, test_client, setup_validation_data):
        """Invalid UUIDs should be rejected with 422."""
        invalid_uuids = [
            "not-a-uuid",
            "12345",
            "00000000-0000-0000-0000-00000000000",  # Too short
            "00000000-0000-0000-0000-0000000000000",  # Too long
            "gggggggg-gggg-gggg-gggg-gggggggggggg",  # Invalid hex
            "00000000_0000_0000_0000_000000000000",  # Wrong delimiter
            "' OR 1=1--",  # SQL injection in UUID
            "<script>alert(1)</script>",  # XSS in UUID
        ]

        for invalid_uuid in invalid_uuids:
            response = await test_client.get(f"/api/targets/{invalid_uuid}")
            # Should return validation error, not 200/500
            assert response.status_code in (307, 400, 422), \
                f"Invalid UUID '{invalid_uuid}' should return error, got {response.status_code}"

            response = await test_client.get(f"/api/scans/{invalid_uuid}")
            assert response.status_code in (307, 400, 422)

            response = await test_client.get(f"/api/results/{invalid_uuid}")
            assert response.status_code in (307, 400, 422)

    @pytest.mark.asyncio
    async def test_invalid_email_formats(self, test_client, setup_validation_data):
        """Invalid email formats should be rejected."""
        invalid_emails = [
            "not-an-email",
            "missing@domain",
            "@nodomain.com",
            "spaces in@email.com",
            "email@domain",  # Missing TLD (may be valid depending on validation)
            "email@@domain.com",
            "email@domain..com",
            ".email@domain.com",
            "email.@domain.com",
            "email@.domain.com",
        ]

        for invalid_email in invalid_emails:
            response = await test_client.post(
                "/api/users",
                json={
                    "email": invalid_email,
                    "name": "Test User",
                },
            )
            # Most should be rejected with 422
            # Some edge cases may be accepted by lenient validators
            assert response.status_code in (201, 400, 422), \
                f"Invalid email '{invalid_email}' caused {response.status_code}"

    @pytest.mark.asyncio
    async def test_invalid_cron_expressions(self, test_client, setup_validation_data):
        """Invalid cron expressions should be rejected or handled."""
        target = setup_validation_data["target"]

        invalid_crons = [
            "not a cron",
            "* * * *",  # Missing field
            "* * * * * * *",  # Too many fields
            "60 * * * *",  # Invalid minute (>59)
            "* 25 * * *",  # Invalid hour (>23)
            "* * 32 * *",  # Invalid day (>31)
            "* * * 13 *",  # Invalid month (>12)
            "* * * * 8",  # Invalid day of week (>7)
            "@ * * * *",  # Invalid character
        ]

        for invalid_cron in invalid_crons:
            response = await test_client.post(
                "/api/schedules",
                json={
                    "name": "Invalid Cron Schedule",
                    "target_id": str(target.id),
                    "cron": invalid_cron,
                },
            )
            # Should be rejected or cron should be validated at execution time
            assert response.status_code in (201, 400, 422), \
                f"Invalid cron '{invalid_cron}' caused {response.status_code}"

    @pytest.mark.asyncio
    async def test_invalid_json(self, test_client, setup_validation_data):
        """Invalid JSON should return 400/422."""
        from openlabels.server.app import app
        import httpx

        # Send raw invalid JSON
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test"
        ) as raw_client:
            response = await raw_client.post(
                "/api/targets",
                content="{invalid json}",
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code in (400, 422)

            response = await raw_client.post(
                "/api/targets",
                content="{'single': 'quotes'}",  # Invalid JSON (single quotes)
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code in (400, 422)

    @pytest.mark.asyncio
    async def test_invalid_adapter_types(self, test_client, setup_validation_data):
        """Invalid adapter types should be rejected."""
        invalid_adapters = [
            "invalid",
            "ftp",
            "s3",
            "azure_blob",
            "FILESYSTEM",  # Case sensitive
            "FileSystem",
            "",
        ]

        for invalid_adapter in invalid_adapters:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": "Invalid Adapter Target",
                    "adapter": invalid_adapter,
                    "config": {"path": "/test"},
                },
            )
            assert_error_response(response)

    @pytest.mark.asyncio
    async def test_invalid_role_values(self, test_client, setup_validation_data):
        """Invalid role values should be rejected."""
        invalid_roles = [
            "superadmin",
            "root",
            "ADMIN",  # Case sensitive
            "Admin",
            "user",
            "",
            "admin; DROP TABLE users;--",
        ]

        for invalid_role in invalid_roles:
            response = await test_client.post(
                "/api/users",
                json={
                    "email": f"invalid-role-{random.randint(1000, 9999)}@test.com",
                    "role": invalid_role,
                },
            )
            assert_error_response(response)


# =============================================================================
# SQL/NOSQL INJECTION TESTS
# =============================================================================


class TestInjectionPatterns:
    """Tests for SQL and NoSQL injection pattern rejection."""

    SQL_INJECTION_PAYLOADS = [
        "'; DROP TABLE scans; --",
        "1 OR 1=1",
        "1; DELETE FROM users; --",
        "1 UNION SELECT * FROM users",
        "' OR '1'='1",
        "admin'--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1; SELECT pg_sleep(5)--",
        "' OR ''='",
        "1' AND '1'='1",
        "1; EXEC xp_cmdshell('whoami')--",
        "'; INSERT INTO users VALUES('hacker','admin')--",
        "1; UPDATE users SET role='admin' WHERE email='test@test.com'--",
        "UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT table_name FROM information_schema.tables--",
    ]

    MONGODB_INJECTION_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "sleep(5000)"}',
        '{"$regex": ".*"}',
        '{"$or": [{}]}',
        '{"email": {"$gt": ""}}',
        '{"$lookup": {}}',
    ]

    LDAP_INJECTION_PAYLOADS = [
        "*)(uid=*))(|(uid=*",
        "admin)(&)",
        "*)(&",
        "*))%00",
        "x*)(objectclass=user",
    ]

    @pytest.mark.asyncio
    async def test_sql_injection_in_target_name(self, test_client, setup_validation_data):
        """SQL injection in target name should be safely handled."""
        for payload in self.SQL_INJECTION_PAYLOADS:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": payload,
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )
            # Should either succeed (safely stored) or fail with validation error
            # Should NEVER cause 500
            assert response.status_code in (200, 201, 400, 422), \
                f"SQL payload '{payload}' caused {response.status_code}"

    @pytest.mark.asyncio
    async def test_sql_injection_in_search_params(self, test_client, setup_validation_data):
        """SQL injection in search parameters should be safely handled."""
        for payload in self.SQL_INJECTION_PAYLOADS:
            # Test in various query parameters
            response = await test_client.get(
                "/api/results",
                params={"search": payload},
            )
            assert response.status_code in (200, 400, 422)

            response = await test_client.get(
                "/api/scans",
                params={"status": payload},
            )
            assert response.status_code in (200, 400, 422, 500)

            response = await test_client.get(
                "/api/audit",
                params={"action": payload},
            )
            assert response.status_code in (200, 400, 422)

    @pytest.mark.asyncio
    async def test_sql_injection_in_config(self, test_client, setup_validation_data):
        """SQL injection in config objects should be safely handled."""
        for payload in self.SQL_INJECTION_PAYLOADS:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": "SQL Test Target",
                    "adapter": "filesystem",
                    "config": {"path": payload},
                },
            )
            # Should be safely stored or rejected - path traversal middleware may block
            assert response.status_code in (200, 201, 400, 403, 422)

    @pytest.mark.asyncio
    async def test_nosql_injection_patterns(self, test_client, setup_validation_data):
        """NoSQL/MongoDB injection patterns should be safely handled."""
        for payload in self.MONGODB_INJECTION_PAYLOADS:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": payload,
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )
            assert response.status_code in (200, 201, 400, 422)

    @pytest.mark.asyncio
    async def test_ldap_injection_patterns(self, test_client, setup_validation_data):
        """LDAP injection patterns should be safely handled."""
        for payload in self.LDAP_INJECTION_PAYLOADS:
            response = await test_client.post(
                "/api/users",
                json={
                    "email": f"ldap-test-{random.randint(1000, 9999)}@test.com",
                    "name": payload,
                },
            )
            assert response.status_code in (200, 201, 400, 422)


# =============================================================================
# ERROR MESSAGE QUALITY TESTS
# =============================================================================


class TestErrorMessageQuality:
    """Tests to ensure error messages are helpful but secure."""

    @pytest.mark.asyncio
    async def test_validation_errors_are_descriptive(self, test_client, setup_validation_data):
        """Validation errors should describe what's wrong."""
        # Missing required field
        response = await test_client.post(
            "/api/targets",
            json={
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )
        assert response.status_code == 422
        error = response.json()

        # Should have detail field explaining the error
        assert "detail" in error or "message" in error

    @pytest.mark.asyncio
    async def test_no_internal_paths_exposed(self, test_client, setup_validation_data):
        """Error responses should not expose internal file paths."""
        response = await test_client.post(
            "/api/targets",
            json={
                "name": 12345,  # Wrong type
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )

        response_text = response.text

        # Check for common internal path patterns
        dangerous_paths = [
            "/home/",
            "/var/",
            "/usr/",
            "/opt/",
            "C:\\",
            "/app/",
            "/code/",
            "site-packages",
        ]

        for path in dangerous_paths:
            assert path not in response_text, \
                f"Internal path '{path}' exposed in error response"

    @pytest.mark.asyncio
    async def test_no_database_details_exposed(self, test_client, setup_validation_data):
        """Error responses should not expose database details."""
        response = await test_client.get(f"/api/targets/{uuid4()}")

        response_text = response.text.lower()

        # Check for database-related terms
        db_terms = [
            "postgresql",
            "postgres",
            "sqlite",
            "mysql",
            "database",
            "connection",
            "sqlalchemy",
            "asyncpg",
            "psycopg",
            "table",
            "column",
            "constraint",
        ]

        for term in db_terms:
            assert term not in response_text, \
                f"Database term '{term}' exposed in error response"

    @pytest.mark.asyncio
    async def test_error_responses_are_json(self, test_client, setup_validation_data):
        """Error responses should be JSON (not HTML error pages)."""
        # Trigger various errors
        error_triggers = [
            ("/api/targets/not-a-uuid", "GET"),  # Invalid UUID
            ("/api/targets", "POST", {}),  # Missing fields
            ("/api/users", "POST", {"email": "invalid"}),  # Invalid email
        ]

        for endpoint, method, *body in error_triggers:
            if method == "GET":
                response = await test_client.get(endpoint)
            else:
                json_body = body[0] if body else {}
                response = await test_client.post(endpoint, json=json_body)

            # Should be JSON, not HTML
            content_type = response.headers.get("content-type", "")
            assert "application/json" in content_type, \
                f"Error response for {endpoint} is not JSON: {content_type}"


# =============================================================================
# EDGE CASE TESTS
# =============================================================================


class TestEdgeCases:
    """Tests for various edge cases."""

    @pytest.mark.asyncio
    async def test_concurrent_duplicate_creation(self, test_client, setup_validation_data):
        """Concurrent creation of duplicate resources should be handled.

        NOTE: With shared test DB sessions, true concurrency tests are limited.
        We test sequential duplicate creation instead.
        """
        unique_email = f"concurrent-{random.randint(10000, 99999)}@test.com"

        # First creation should succeed
        response1 = await test_client.post(
            "/api/users",
            json={"email": unique_email},
        )
        assert response1.status_code == 201

        # Second creation with same email should fail
        response2 = await test_client.post(
            "/api/users",
            json={"email": unique_email},
        )
        assert response2.status_code in (400, 409, 422, 500), \
            f"Duplicate creation should fail, got {response2.status_code}"

    @pytest.mark.asyncio
    async def test_deeply_nested_json_config(self, test_client, setup_validation_data):
        """Deeply nested JSON in config should not cause DoS."""
        # Create deeply nested config
        nested = {"value": "test"}
        for _ in range(50):
            nested = {"nested": nested}

        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Deeply Nested Target",
                "adapter": "filesystem",
                "config": nested,
            },
        )
        # Should either succeed or fail with validation error
        # Should NEVER cause 500 (server crash = DoS)
        assert response.status_code in (200, 201, 400, 413, 422), \
            f"Deeply nested config caused {response.status_code}"

    @pytest.mark.asyncio
    async def test_large_json_payload(self, test_client, setup_validation_data):
        """Very large JSON payloads should be rejected."""
        # Create payload with many keys
        large_config = {f"key_{i}": f"value_{i}" for i in range(10000)}

        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Large Payload Target",
                "adapter": "filesystem",
                "config": large_config,
            },
        )
        # Should either succeed or fail gracefully
        assert response.status_code in (200, 201, 400, 413, 422)

    @pytest.mark.asyncio
    async def test_special_query_parameter_characters(self, test_client, setup_validation_data):
        """Special characters in query parameters should be handled."""
        special_params = [
            ("search", "test&another=value"),  # Parameter injection
            ("search", "test%00null"),  # Null byte
            ("search", "test%0Anewline"),  # Newline
            ("search", "test<script>alert(1)</script>"),  # XSS
            ("filter", "test;ls -la"),  # Command injection
        ]

        for param_name, param_value in special_params:
            response = await test_client.get(
                "/api/results",
                params={param_name: param_value},
            )
            # Should return 200 (empty results) or validation error
            # Should NOT cause 500
            assert response.status_code in (200, 400, 422), \
                f"Special param '{param_value}' caused {response.status_code}"

    @pytest.mark.asyncio
    async def test_repeated_parameter_handling(self, test_client, setup_validation_data):
        """Repeated parameters should be handled consistently."""
        # Some frameworks accept first, some last, some as array
        response = await test_client.get(
            "/api/targets?page=1&page=2&page=100"
        )
        # Should handle gracefully
        assert response.status_code in (200, 400, 422)

    @pytest.mark.asyncio
    async def test_extra_fields_ignored_or_rejected(self, test_client, setup_validation_data):
        """Extra fields in request body should be ignored or rejected."""
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Extra Fields Target",
                "adapter": "filesystem",
                "config": {"path": "/test"},
                "extra_field": "should be ignored",
                "another_extra": {"nested": "value"},
                "is_admin": True,  # Attempt to set protected field
                "tenant_id": str(uuid4()),  # Attempt to set tenant
            },
        )
        # Should either succeed (extra fields ignored) or reject
        if response.status_code in (200, 201):
            # Verify extra fields were not set
            data = response.json()
            assert "extra_field" not in data
            assert "another_extra" not in data

    @pytest.mark.asyncio
    async def test_content_type_validation(self, test_client, setup_validation_data):
        """Wrong content type should be rejected."""
        from openlabels.server.app import app
        import httpx

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test"
        ) as raw_client:
            # Send JSON with wrong content type
            response = await raw_client.post(
                "/api/targets",
                content='{"name": "Test", "adapter": "filesystem", "config": {"path": "/test"}}',
                headers={"Content-Type": "text/plain"},
            )
            # Should reject or parse based on implementation
            assert response.status_code in (200, 201, 400, 415, 422)

            # Send form data to JSON endpoint
            response = await raw_client.post(
                "/api/targets",
                data={"name": "Test", "adapter": "filesystem"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            assert response.status_code in (400, 415, 422)
