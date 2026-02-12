"""
Unified test configuration for OpenLabels.

Combines fixtures and utilities from the merged OpenRisk and ScrubIQ codebases.
Handles optional dependencies (Qt, OCR, ML) gracefully.
"""

import sys
import pytest
from typing import List, Dict, Any

# =============================================================================
# QT/GUI HANDLING
# =============================================================================

_qt_available = False
_qt_skip_reason = "Qt not available"

try:
    from PySide6 import QtWidgets
    _qt_available = True
except ImportError as e:
    _qt_skip_reason = f"PySide6 not installed: {e}"
except OSError as e:
    _qt_skip_reason = f"Qt system libraries missing: {e}"


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "gui: mark test as requiring Qt GUI"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )


def pytest_collection_modifyitems(config, items):
    """Skip tests based on available dependencies."""
    for item in items:
        # Skip GUI tests if Qt is not available
        if not _qt_available:
            if "test_gui" in item.nodeid or "gui" in item.keywords:
                item.add_marker(pytest.mark.skip(reason=_qt_skip_reason))


if not _qt_available:
    @pytest.fixture
    def qtbot():
        pytest.skip(_qt_skip_reason)


# =============================================================================
# CORE TYPE IMPORTS
# =============================================================================

from openlabels.core.types import Span, Tier, RiskTier


# =============================================================================
# SPAN FACTORY FUNCTIONS
# =============================================================================

def make_span(
    text: str,
    start: int = 0,
    entity_type: str = "NAME",
    confidence: float = 0.9,
    detector: str = "test",
    tier: int = 2,
    **kwargs
) -> Span:
    """
    Factory function to create a valid Span for testing.

    Automatically calculates end position from start + len(text).
    This ensures span text length always matches span boundaries.

    Args:
        text: The span text content
        start: Start position in document (default 0)
        entity_type: Entity type (default NAME)
        confidence: Confidence score 0.0-1.0 (default 0.9)
        detector: Detector name (default "test")
        tier: Authority tier 1-4 (default 2 = PATTERN)
        **kwargs: Additional Span fields (needs_review, etc.)

    Returns:
        A valid Span object
    """
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
        **kwargs
    )


def make_spans_from_text(text: str, annotations: list) -> List[Span]:
    """
    Create spans from a text string and list of annotations.

    Args:
        text: The source text
        annotations: List of (start, end, entity_type, confidence, detector, tier) tuples
            or dicts with those keys

    Returns:
        List of Span objects

    Example:
        text = "John Smith lives in NYC"
        spans = make_spans_from_text(text, [
            (0, 10, "NAME", 0.9, "ml", 1),
            (20, 23, "ADDRESS", 0.8, "pattern", 2),
        ])
    """
    spans = []
    for ann in annotations:
        if isinstance(ann, dict):
            start = ann["start"]
            end = ann["end"]
            entity_type = ann.get("entity_type", "NAME")
            confidence = ann.get("confidence", 0.9)
            detector = ann.get("detector", "test")
            tier = ann.get("tier", 2)
        else:
            start, end, entity_type, confidence, detector, tier = ann

        spans.append(Span(
            start=start,
            end=end,
            text=text[start:end],
            entity_type=entity_type,
            confidence=confidence,
            detector=detector,
            tier=Tier.from_value(tier),
        ))
    return spans


# =============================================================================
# FIXTURES - Span Factories
# =============================================================================

@pytest.fixture
def span_factory():
    """Fixture providing the make_span factory function."""
    return make_span


@pytest.fixture
def spans_from_text():
    """Fixture providing the make_spans_from_text factory function."""
    return make_spans_from_text


# =============================================================================
# TEST DATA - Common Test Texts
# =============================================================================

CLINICAL_NOTE = """
Patient: John Smith
DOB: 01/15/1980
MRN: 123456789

Dr. Sarah Johnson, MD reviewed the patient's case.
The patient presents with chest pain. Contact: 555-123-4567.
Email: john.smith@email.com

Address: 123 Main Street, Springfield, IL 62701
"""

ID_CARD_TEXT = """
DRIVER'S LICENSE
DLN: D123-4567-8901
CLASS: C
NAME: JOHN SMITH
DOB: 01/15/1980
DUPS: 000
4bEXP: 01/15/2028
RESTR: NONE
"""

SHIPPING_CONTEXT = """
Your package has been shipped!
USPS Tracking: 9400111899223456789012
FedEx: 123456789012
Estimated delivery: January 25, 2026
"""

FINANCIAL_TEXT = """
Account Statement
Name: Jane Doe
Account: 1234567890
Routing: 021000021
SSN: 123-45-6789
Credit Card: 4532015112830366
"""

SECRETS_TEXT = """
# Configuration (DO NOT COMMIT)
AWS_ACCESS_KEY_ID=AKIATESTKEY1234567890
AWS_SECRET_ACCESS_KEY=test/secret/key/for/unit/testing/only1234567890
GITHUB_TOKEN=ghp_test1234567890test1234567890test1234
STRIPE_KEY=sk_test_fake_key_for_testing_only_1234
"""


@pytest.fixture
def clinical_note():
    """Sample clinical note text for testing."""
    return CLINICAL_NOTE


@pytest.fixture
def id_card_text():
    """Sample ID card text for testing."""
    return ID_CARD_TEXT


@pytest.fixture
def shipping_context():
    """Sample shipping/tracking context for testing."""
    return SHIPPING_CONTEXT


@pytest.fixture
def financial_text():
    """Sample financial document text for testing."""
    return FINANCIAL_TEXT


@pytest.fixture
def secrets_text():
    """Sample text containing secrets for testing."""
    return SECRETS_TEXT


# =============================================================================
# FIXTURES - Mock Objects
# =============================================================================

@pytest.fixture
def mock_config():
    """
    Mock configuration for detector initialization.

    Returns a dict that can be used as **kwargs for detector constructors.
    """
    return {
        "min_confidence": 0.7,
        "enabled_detectors": ["checksum", "pattern", "financial", "government"],
        "max_file_size": 10 * 1024 * 1024,  # 10MB
        "timeout_seconds": 30,
    }


@pytest.fixture
def sample_ssns():
    """Sample valid and invalid SSNs for testing."""
    return {
        "valid": [
            "123-45-6789",
            "078-05-1120",
            "219-09-9999",
        ],
        "invalid": [
            "000-00-0000",  # All zeros
            "666-00-0000",  # 666 prefix
            "900-00-0000",  # 9xx prefix
            "123-00-6789",  # Middle zeros
            "123-45-0000",  # Last zeros
        ],
    }


@pytest.fixture
def sample_credit_cards():
    """Sample valid and invalid credit card numbers for testing."""
    return {
        "valid": [
            "4532015112830366",  # Visa
            "5425233430109903",  # Mastercard
            "374245455400126",   # Amex
            "6011000990139424",  # Discover
        ],
        "invalid": [
            "1234567890123456",  # Fails Luhn
            "0000000000000000",  # All zeros
            "4532015112830367",  # Off by one
        ],
    }


@pytest.fixture
def sample_ibans():
    """Sample valid and invalid IBANs for testing."""
    return {
        "valid": [
            "GB82WEST12345698765432",  # UK
            "DE89370400440532013000",  # Germany
            "FR1420041010050500013M02606",  # France
        ],
        "invalid": [
            "GB82WEST12345698765433",  # Bad checksum
            "XX00BANK00000000000000",  # Invalid country
            "TOOLONG" * 10,  # Too long
        ],
    }


# =============================================================================
# ASYNC TEST SUPPORT
# =============================================================================

# =============================================================================
# DATABASE FIXTURES (for API tests)
# =============================================================================

import os

def _try_setup_system_postgres():
    """Auto-detect and configure system PostgreSQL for testing.

    Starts the service if stopped, sets the postgres password, and
    creates the test database.  Returns the async connection URL on
    success or ``None`` on failure.
    """
    import shutil
    import subprocess

    if not shutil.which("pg_isready"):
        return None

    # Start PostgreSQL if not running
    if subprocess.run(
        ["pg_isready", "-h", "localhost", "-p", "5432"],
        capture_output=True,
    ).returncode != 0:
        for ver in ("16", "15"):
            if subprocess.run(
                ["pg_ctlcluster", ver, "main", "start"],
                capture_output=True,
            ).returncode == 0:
                break
        import time
        time.sleep(2)

    if subprocess.run(
        ["pg_isready", "-h", "localhost", "-p", "5432"],
        capture_output=True,
    ).returncode != 0:
        return None

    # Connect via local socket (trust auth), sudo peer auth, or TCP
    psql_prefix = None
    connection_env = os.environ.copy()
    for cmd in (
        ["psql", "-U", "postgres", "-d", "postgres", "-c", "SELECT 1"],
        ["sudo", "-u", "postgres", "psql", "-d", "postgres", "-c", "SELECT 1"],
        ["psql", "-h", "localhost", "-U", "postgres", "-d", "postgres", "-c", "SELECT 1"],
    ):
        env = os.environ.copy()
        if "-h" in cmd:
            env["PGPASSWORD"] = "test"
        if subprocess.run(cmd, capture_output=True, env=env).returncode == 0:
            psql_prefix = cmd[:-2]  # drop the "-c" and "SELECT 1"
            connection_env = env
            break

    if psql_prefix is None:
        return None

    env = connection_env

    # Set password (idempotent)
    subprocess.run(
        psql_prefix + ["-c", "ALTER ROLE postgres WITH PASSWORD 'test';"],
        capture_output=True, env=env,
    )

    # Create test database if missing
    result = subprocess.run(
        psql_prefix + ["-tAc", "SELECT 1 FROM pg_database WHERE datname='openlabels_test'"],
        capture_output=True, text=True, env=env,
    )
    if "1" not in (result.stdout or ""):
        subprocess.run(
            psql_prefix + ["-c", "CREATE DATABASE openlabels_test;"],
            capture_output=True, env=env,
        )

    # Verify TCP connection with password
    env2 = os.environ.copy()
    env2["PGPASSWORD"] = "test"
    if subprocess.run(
        ["psql", "-h", "localhost", "-U", "postgres", "-d", "openlabels_test", "-c", "SELECT 1"],
        capture_output=True, env=env2,
    ).returncode == 0:
        return "postgresql+asyncpg://postgres:test@localhost:5432/openlabels_test"

    return None


@pytest.fixture(scope="session")
def database_url():
    """
    Get database URL for testing.

    Uses TEST_DATABASE_URL env var if set (PostgreSQL),
    otherwise auto-detects and configures system PostgreSQL.
    Returns None if no PostgreSQL is available (tests requiring DB
    will be skipped).

    IMPORTANT: Must be a PostgreSQL URL (postgresql+asyncpg://...).
    SQLite is NOT supported because models use JSONB.

    To run with PostgreSQL locally:
        docker run -d --name test-postgres \\
            -e POSTGRES_PASSWORD=test \\
            -e POSTGRES_DB=openlabels_test \\
            -p 5432:5432 postgres:15

        export TEST_DATABASE_URL="postgresql+asyncpg://postgres:test@localhost:5432/openlabels_test"
        pytest
    """
    url = os.getenv("TEST_DATABASE_URL")
    if url and "postgresql" not in url:
        # SQLite and other databases are not supported - models use JSONB
        return None
    # Always run auto-setup: it's idempotent and ensures the password is
    # set and the test database exists even when pytest-env pre-populates
    # TEST_DATABASE_URL (which would otherwise skip the setup entirely).
    auto_url = _try_setup_system_postgres()
    if url:
        return url
    return auto_url


# Track whether tables have been created in the test database
_tables_initialized = False


@pytest.fixture
async def test_db(database_url):
    """
    Create a test database session.

    Requires PostgreSQL (models use JSONB which SQLite doesn't support).
    Creates a fresh engine per test (required by pytest-asyncio's per-test
    event loop), but only runs DDL once. Uses TRUNCATE for fast cleanup.
    """
    if not database_url:
        pytest.skip("PostgreSQL not available - set TEST_DATABASE_URL")

    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from openlabels.server.models import Base
    from sqlalchemy import text

    global _tables_initialized

    engine = create_async_engine(
        database_url,
        echo=False,
        pool_size=5,
        max_overflow=5,
        connect_args={"timeout": 10, "statement_cache_size": 0},
    )

    try:
        if not _tables_initialized:
            # First test: drop and recreate schema for clean slate
            # Terminate stale connections first to avoid DROP SCHEMA
            # hanging on lock contention from killed test runs
            async with engine.begin() as conn:
                await conn.execute(text(
                    "SELECT pg_terminate_backend(pid) "
                    "FROM pg_stat_activity "
                    "WHERE datname = current_database() "
                    "AND pid != pg_backend_pid()"
                ))
            async with engine.begin() as conn:
                await conn.execute(text("DROP SCHEMA public CASCADE"))
                await conn.execute(text("CREATE SCHEMA public"))
                await conn.run_sync(Base.metadata.create_all)
            _tables_initialized = True
        else:
            # Subsequent tests: truncate all tables (fast, no DDL,
            # avoids asyncpg statement cache invalidation issues)
            try:
                async with engine.begin() as conn:
                    table_names = [t.name for t in reversed(Base.metadata.sorted_tables)]
                    if table_names:
                        await conn.execute(text(
                            f"TRUNCATE TABLE {', '.join(table_names)} CASCADE"
                        ))
            except Exception:
                # If truncate fails (e.g. missing tables from schema changes),
                # fall back to full schema recreation
                async with engine.begin() as conn:
                    await conn.execute(text("DROP SCHEMA public CASCADE"))
                    await conn.execute(text("CREATE SCHEMA public"))
                    await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:
        await engine.dispose()
        pytest.fail(f"PostgreSQL not reachable at {database_url}: {exc}")

    try:
        async_session = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        async with async_session() as session:
            yield session
    finally:
        await engine.dispose()


@pytest.fixture
async def test_client(test_db):
    """
    Create a test client for API testing.

    Overrides the database dependency to use the test database.
    Also overrides authentication to use a mock user for testing.

    Uses randomized test data to prevent collisions in parallel test runs.
    """
    import random
    import string
    from uuid import UUID
    from httpx import AsyncClient, ASGITransport
    from openlabels.server.app import app
    from openlabels.server.db import get_session
    from openlabels.server.dependencies import get_db_session
    from openlabels.auth.dependencies import get_current_user, get_optional_user, require_admin, CurrentUser
    from openlabels.server.models import Tenant, User

    # Generate unique suffix to prevent test data collisions
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    # Create test tenant and user in the database with randomized names
    test_tenant = Tenant(
        name=f"Test Tenant {suffix}",
        azure_tenant_id=f"test-tenant-id-{suffix}",
    )
    test_db.add(test_tenant)
    await test_db.flush()

    test_user = User(
        tenant_id=test_tenant.id,
        email=f"test-{suffix}@localhost",
        name=f"Test User {suffix}",
        role="admin",
    )
    test_db.add(test_user)
    await test_db.commit()

    # Refresh to ensure all attributes are loaded from DB
    await test_db.refresh(test_tenant)
    await test_db.refresh(test_user)

    async def override_get_session():
        yield test_db

    def _create_test_current_user():
        """Create a CurrentUser from the test user."""
        return CurrentUser(
            id=test_user.id,
            tenant_id=test_tenant.id,
            email=test_user.email,
            name=test_user.name,
            role=str(test_user.role),  # Ensure role is a string, not enum
        )

    async def override_get_current_user():
        """Return a mock current user for testing."""
        return _create_test_current_user()

    async def override_get_optional_user():
        """Return a mock current user for testing (for optional auth routes)."""
        return _create_test_current_user()

    async def override_require_admin():
        """Return a mock admin user for testing."""
        return _create_test_current_user()

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_db_session] = override_get_session
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_optional_user] = override_get_optional_user
    app.dependency_overrides[require_admin] = override_require_admin

    # Disable rate limiting for tests - collect all limiters from various modules
    from openlabels.server.app import limiter as app_limiter
    from openlabels.server.routes.remediation import limiter as remediation_limiter
    from openlabels.server.routes.scans import limiter as scans_limiter
    from openlabels.server.routes.auth import limiter as auth_limiter

    limiters = [app_limiter, remediation_limiter, scans_limiter, auth_limiter]
    original_states = [l.enabled for l in limiters]
    for l in limiters:
        l.enabled = False

    # Patch lifespan-related functions to prevent the app from creating its
    # own DB engine, connecting to Redis, or starting the scheduler during tests.
    # The test_db fixture already provides the DB session.
    from unittest.mock import AsyncMock, patch, MagicMock
    mock_cache = MagicMock()
    mock_cache.is_redis_connected = False
    with patch("openlabels.server.lifespan.init_db", new_callable=AsyncMock), \
         patch("openlabels.server.lifespan.close_db", new_callable=AsyncMock), \
         patch("openlabels.server.lifespan.get_cache_manager", new_callable=AsyncMock, return_value=mock_cache), \
         patch("openlabels.server.lifespan.close_cache", new_callable=AsyncMock):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://localhost") as client:
            yield client

    # Re-enable rate limiting
    for l, state in zip(limiters, original_states):
        l.enabled = state

    app.dependency_overrides.clear()
