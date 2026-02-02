"""Tests for database models."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest


class TestTenantModel:
    """Tests for Tenant model."""

    def test_tenant_creation(self):
        """Test creating a tenant."""
        from openlabels.server.models import Tenant

        tenant = Tenant(
            name="Test Company",
            azure_tenant_id="test-azure-id",
        )

        assert tenant.name == "Test Company"
        assert tenant.azure_tenant_id == "test-azure-id"

    def test_tenant_has_uuid_id(self):
        """Test tenant has UUID id field."""
        from openlabels.server.models import Tenant

        # Model should have id field configured
        assert hasattr(Tenant, "id")


class TestUserModel:
    """Tests for User model."""

    def test_user_creation(self):
        """Test creating a user."""
        from openlabels.server.models import User

        user = User(
            email="test@example.com",
            name="Test User",
            role="viewer",
        )

        assert user.email == "test@example.com"
        assert user.role == "viewer"

    def test_user_roles(self):
        """Test user roles are valid."""
        from openlabels.server.models import User

        # Should accept admin and viewer roles
        admin = User(email="admin@test.com", role="admin")
        viewer = User(email="viewer@test.com", role="viewer")

        assert admin.role == "admin"
        assert viewer.role == "viewer"


class TestSessionModel:
    """Tests for Session model."""

    def test_session_creation(self):
        """Test creating a session."""
        from openlabels.server.models import Session

        session = Session(
            id="session-123",
            data={"access_token": "token"},
            expires_at=datetime.now(timezone.utc),
        )

        assert session.id == "session-123"
        assert session.data == {"access_token": "token"}

    def test_session_data_is_jsonb(self):
        """Test session data can store complex structures."""
        from openlabels.server.models import Session

        session = Session(
            id="session-456",
            data={
                "access_token": "token",
                "claims": {"sub": "user123", "email": "test@test.com"},
                "scopes": ["read", "write"],
            },
            expires_at=datetime.now(timezone.utc),
        )

        assert session.data["claims"]["sub"] == "user123"


class TestPendingAuthModel:
    """Tests for PendingAuth model."""

    def test_pending_auth_creation(self):
        """Test creating pending auth."""
        from openlabels.server.models import PendingAuth

        pending = PendingAuth(
            state="random-state-token",
            redirect_uri="http://app/callback",
            callback_url="http://localhost:8000/auth/callback",
        )

        assert pending.state == "random-state-token"
        assert pending.redirect_uri == "http://app/callback"


class TestScanJobModel:
    """Tests for ScanJob model."""

    def test_scan_job_creation(self):
        """Test creating a scan job."""
        from openlabels.server.models import ScanJob

        job = ScanJob(
            status="pending",
        )

        assert job.status == "pending"

    def test_scan_job_statuses(self):
        """Test scan job status values."""
        from openlabels.server.models import ScanJob

        valid_statuses = ["pending", "running", "completed", "failed", "cancelled"]

        for status in valid_statuses:
            job = ScanJob(status=status)
            assert job.status == status


class TestScanResultModel:
    """Tests for ScanResult model."""

    def test_scan_result_creation(self):
        """Test creating a scan result."""
        from openlabels.server.models import ScanResult

        result = ScanResult(
            file_path="/path/to/file.txt",
            file_name="file.txt",
            risk_score=75,
            risk_tier="HIGH",
            entity_counts={"SSN": 3, "EMAIL": 5},
            total_entities=8,
        )

        assert result.risk_score == 75
        assert result.entity_counts["SSN"] == 3

    def test_scan_result_entity_counts_is_jsonb(self):
        """Test entity_counts can store dict."""
        from openlabels.server.models import ScanResult

        result = ScanResult(
            file_path="/test.pdf",
            file_name="test.pdf",
            entity_counts={"PERSON": 10, "ORG": 5, "EMAIL": 20},
        )

        assert result.entity_counts["PERSON"] == 10


class TestScanTargetModel:
    """Tests for ScanTarget model."""

    def test_scan_target_creation(self):
        """Test creating a scan target."""
        from openlabels.server.models import ScanTarget

        target = ScanTarget(
            name="Production Share",
            adapter="filesystem",
            config={"path": "/data/share"},
        )

        assert target.name == "Production Share"
        assert target.adapter == "filesystem"

    def test_scan_target_adapters(self):
        """Test scan target adapter types."""
        from openlabels.server.models import ScanTarget

        adapters = ["filesystem", "sharepoint", "onedrive"]

        for adapter in adapters:
            target = ScanTarget(name=f"{adapter} target", adapter=adapter, config={})
            assert target.adapter == adapter


class TestSensitivityLabelModel:
    """Tests for SensitivityLabel model."""

    def test_sensitivity_label_creation(self):
        """Test creating a sensitivity label."""
        from openlabels.server.models import SensitivityLabel

        label = SensitivityLabel(
            name="Confidential",
        )

        assert label.name == "Confidential"

    def test_sensitivity_label_has_name_field(self):
        """Test SensitivityLabel has name field."""
        from openlabels.server.models import SensitivityLabel

        assert hasattr(SensitivityLabel, 'name')


class TestLabelRuleModel:
    """Tests for LabelRule model."""

    def test_label_rule_creation(self):
        """Test creating a label rule."""
        from openlabels.server.models import LabelRule

        rule = LabelRule(
            rule_type="risk_tier",
            match_value="CRITICAL",
            priority=100,
        )

        assert rule.rule_type == "risk_tier"
        assert rule.match_value == "CRITICAL"
