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
    """Skip GUI tests if Qt is not available."""
    if _qt_available:
        return

    skip_qt = pytest.mark.skip(reason=_qt_skip_reason)
    for item in items:
        if "test_gui" in item.nodeid or "gui" in item.keywords:
            item.add_marker(skip_qt)


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

@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# DATABASE FIXTURES (for API tests)
# =============================================================================

@pytest.fixture
async def test_db():
    """
    Create an in-memory SQLite database for testing.

    Yields a session that rolls back after each test.
    """
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from openlabels.server.models import Base

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        yield session
        await session.rollback()

    await engine.dispose()


@pytest.fixture
async def test_client(test_db):
    """
    Create a test client for API testing.

    Overrides the database dependency to use the test database.
    Also overrides authentication to use a mock user for testing.
    """
    from uuid import UUID
    from httpx import AsyncClient, ASGITransport
    from openlabels.server.app import app
    from openlabels.server.db import get_session
    from openlabels.auth.dependencies import get_current_user, CurrentUser
    from openlabels.server.models import Tenant, User

    # Create test tenant and user in the database
    test_tenant = Tenant(
        name="Test Tenant",
        azure_tenant_id="test-tenant-id",
    )
    test_db.add(test_tenant)
    await test_db.flush()

    test_user = User(
        tenant_id=test_tenant.id,
        email="test@localhost",
        name="Test User",
        role="admin",
    )
    test_db.add(test_user)
    await test_db.commit()

    async def override_get_session():
        yield test_db

    async def override_get_current_user():
        """Return a mock current user for testing."""
        return CurrentUser(
            id=str(test_user.id),
            tenant_id=str(test_tenant.id),
            email=test_user.email,
            name=test_user.name,
            role=test_user.role,
        )

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
