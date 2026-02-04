"""
Tests for database models.

Tests actual model behavior, constraints, defaults, and relationships.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest


class TestTenantModel:
    """Tests for Tenant model behavior."""

    def test_tenant_requires_name(self):
        """Tenant model should require a name."""
        from openlabels.server.models import Tenant

        # Name is required - creating without it should fail at DB level
        # For unit tests, verify the column is configured as non-nullable
        assert Tenant.__table__.c.name.nullable is False

    def test_tenant_id_is_uuid(self):
        """Tenant ID should be a UUID type."""
        from openlabels.server.models import Tenant
        from sqlalchemy.dialects.postgresql import UUID as PG_UUID

        id_column = Tenant.__table__.c.id
        assert isinstance(id_column.type, PG_UUID)

    def test_tenant_has_created_at_default(self):
        """Tenant should have automatic created_at timestamp."""
        from openlabels.server.models import Tenant

        created_at_col = Tenant.__table__.c.created_at
        assert created_at_col.server_default is not None

    def test_tenant_azure_tenant_id_is_optional(self):
        """Azure tenant ID should be optional for non-Azure deployments."""
        from openlabels.server.models import Tenant

        assert Tenant.__table__.c.azure_tenant_id.nullable is True


class TestUserModel:
    """Tests for User model constraints."""

    def test_user_requires_email(self):
        """User email is required."""
        from openlabels.server.models import User

        assert User.__table__.c.email.nullable is False

    def test_user_requires_tenant(self):
        """User must belong to a tenant."""
        from openlabels.server.models import User

        assert User.__table__.c.tenant_id.nullable is False

    def test_user_role_defaults_to_viewer(self):
        """User role should default to 'viewer' for security."""
        from openlabels.server.models import User

        role_col = User.__table__.c.role
        # Check default value
        assert role_col.default.arg == "viewer"

    def test_user_role_enum_values(self):
        """User role must be admin or viewer."""
        from openlabels.server.models import UserRoleEnum

        # Get the enum values
        enum_values = UserRoleEnum.enums
        assert "admin" in enum_values
        assert "viewer" in enum_values
        assert len(enum_values) == 2, "Only admin and viewer roles should exist"

    def test_user_email_unique_per_tenant(self):
        """User email should be unique within a tenant."""
        from openlabels.server.models import User

        # Check for the unique index
        indexes = [idx for idx in User.__table__.indexes if 'email' in str(idx)]
        assert len(indexes) > 0, "Should have index on email"

        # Find the unique constraint
        unique_indexes = [idx for idx in indexes if idx.unique]
        assert len(unique_indexes) > 0, "Email should be unique per tenant"


class TestScanJobModel:
    """Tests for ScanJob model and job lifecycle."""

    def test_job_status_enum_values(self):
        """Job status must be one of the allowed values."""
        from openlabels.server.models import JobStatusEnum

        expected = {'pending', 'running', 'completed', 'failed', 'cancelled'}
        actual = set(JobStatusEnum.enums)
        assert actual == expected

    def test_job_defaults_to_pending(self):
        """New jobs should default to pending status."""
        from openlabels.server.models import ScanJob

        status_col = ScanJob.__table__.c.status
        assert status_col.default.arg == "pending"

    def test_job_tracks_timing(self):
        """Job should have fields to track execution timing."""
        from openlabels.server.models import ScanJob

        table = ScanJob.__table__
        assert 'started_at' in table.c
        assert 'completed_at' in table.c
        assert 'created_at' in table.c

    def test_job_tracks_progress(self):
        """Job should track files scanned and with PII."""
        from openlabels.server.models import ScanJob

        table = ScanJob.__table__
        assert 'files_scanned' in table.c
        assert 'files_with_pii' in table.c

    def test_job_files_scanned_defaults_to_zero(self):
        """Files scanned should default to 0."""
        from openlabels.server.models import ScanJob

        col = ScanJob.__table__.c.files_scanned
        assert col.default.arg == 0


class TestScanResultModel:
    """Tests for ScanResult model constraints."""

    def test_result_requires_file_path(self):
        """Scan result must have file path."""
        from openlabels.server.models import ScanResult

        assert ScanResult.__table__.c.file_path.nullable is False

    def test_result_requires_risk_score(self):
        """Scan result must have a risk score."""
        from openlabels.server.models import ScanResult

        assert ScanResult.__table__.c.risk_score.nullable is False

    def test_result_requires_risk_tier(self):
        """Scan result must have a risk tier."""
        from openlabels.server.models import ScanResult

        assert ScanResult.__table__.c.risk_tier.nullable is False

    def test_risk_tier_enum_values(self):
        """Risk tier must be one of the defined levels."""
        from openlabels.server.models import RiskTierEnum

        expected = {'MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
        actual = set(RiskTierEnum.enums)
        assert actual == expected

    def test_risk_tier_has_correct_order(self):
        """Risk tiers should be ordered from lowest to highest."""
        from openlabels.server.models import RiskTierEnum

        # Enums are defined in order
        tiers = RiskTierEnum.enums
        expected_order = ['MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        assert tiers == expected_order

    def test_result_entity_counts_is_jsonb(self):
        """Entity counts should use JSONB for efficient queries."""
        from openlabels.server.models import ScanResult, JSONB

        col = ScanResult.__table__.c.entity_counts
        assert isinstance(col.type, JSONB)

    def test_result_has_gin_index_on_entities(self):
        """Should have GIN index on entity_counts for JSONB queries."""
        from openlabels.server.models import ScanResult

        indexes = list(ScanResult.__table__.indexes)
        gin_indexes = [idx for idx in indexes if 'entities' in idx.name]
        assert len(gin_indexes) > 0, "Should have GIN index for entity queries"


class TestScanTargetModel:
    """Tests for ScanTarget model."""

    def test_target_adapter_enum_values(self):
        """Adapter type must be one of the supported adapters."""
        from openlabels.server.models import AdapterTypeEnum

        expected = {'filesystem', 'sharepoint', 'onedrive'}
        actual = set(AdapterTypeEnum.enums)
        assert actual == expected

    def test_target_requires_name(self):
        """Scan target must have a name."""
        from openlabels.server.models import ScanTarget

        assert ScanTarget.__table__.c.name.nullable is False

    def test_target_requires_config(self):
        """Scan target must have configuration."""
        from openlabels.server.models import ScanTarget

        assert ScanTarget.__table__.c.config.nullable is False

    def test_target_enabled_defaults_to_true(self):
        """New targets should be enabled by default."""
        from openlabels.server.models import ScanTarget

        col = ScanTarget.__table__.c.enabled
        assert col.default.arg is True


class TestSensitivityLabelModel:
    """Tests for SensitivityLabel model."""

    def test_label_id_is_string_for_mip_guids(self):
        """Label ID should be string to match MIP label GUIDs."""
        from openlabels.server.models import SensitivityLabel
        from sqlalchemy import String

        id_col = SensitivityLabel.__table__.c.id
        assert isinstance(id_col.type, String)

    def test_label_requires_name(self):
        """Sensitivity label must have a name."""
        from openlabels.server.models import SensitivityLabel

        assert SensitivityLabel.__table__.c.name.nullable is False

    def test_label_has_priority(self):
        """Labels should have priority for ordering."""
        from openlabels.server.models import SensitivityLabel

        assert 'priority' in SensitivityLabel.__table__.c


class TestLabelRuleModel:
    """Tests for LabelRule model."""

    def test_rule_type_enum_values(self):
        """Rule type must be one of the allowed values."""
        from openlabels.server.models import LabelRuleTypeEnum

        expected = {'risk_tier', 'entity_type', 'exposure_level', 'custom'}
        actual = set(LabelRuleTypeEnum.enums)
        assert actual == expected

    def test_rule_requires_match_value(self):
        """Rule must have a value to match against."""
        from openlabels.server.models import LabelRule

        assert LabelRule.__table__.c.match_value.nullable is False

    def test_rule_has_priority_for_ordering(self):
        """Rules should have priority for conflict resolution."""
        from openlabels.server.models import LabelRule

        col = LabelRule.__table__.c.priority
        assert col is not None
        assert col.default.arg == 0


class TestJobQueueModel:
    """Tests for JobQueue model (background task queue)."""

    def test_queue_has_retry_mechanism(self):
        """Job queue should support retries."""
        from openlabels.server.models import JobQueue

        table = JobQueue.__table__
        assert 'retry_count' in table.c
        assert 'max_retries' in table.c

    def test_queue_retry_defaults(self):
        """Retry settings should have sensible defaults."""
        from openlabels.server.models import JobQueue

        retry_count = JobQueue.__table__.c.retry_count
        max_retries = JobQueue.__table__.c.max_retries

        assert retry_count.default.arg == 0
        assert max_retries.default.arg == 3

    def test_queue_has_priority(self):
        """Jobs should have priority for ordering."""
        from openlabels.server.models import JobQueue

        col = JobQueue.__table__.c.priority
        assert col is not None
        assert col.default.arg == 50  # Middle priority

    def test_queue_has_worker_tracking(self):
        """Queue should track which worker owns a job."""
        from openlabels.server.models import JobQueue

        assert 'worker_id' in JobQueue.__table__.c

    def test_queue_has_scheduled_for(self):
        """Queue should support delayed/scheduled jobs."""
        from openlabels.server.models import JobQueue

        assert 'scheduled_for' in JobQueue.__table__.c


class TestExposureLevelEnum:
    """Tests for ExposureLevel enum."""

    def test_exposure_level_values(self):
        """Exposure levels should cover access spectrum."""
        from openlabels.server.models import ExposureLevelEnum

        expected = {'PRIVATE', 'INTERNAL', 'ORG_WIDE', 'PUBLIC'}
        actual = set(ExposureLevelEnum.enums)
        assert actual == expected

    def test_exposure_level_order(self):
        """Exposure levels should be ordered from most to least restrictive."""
        from openlabels.server.models import ExposureLevelEnum

        levels = ExposureLevelEnum.enums
        expected_order = ['PRIVATE', 'INTERNAL', 'ORG_WIDE', 'PUBLIC']
        assert levels == expected_order


class TestAuditLogModel:
    """Tests for AuditLog model."""

    def test_audit_action_enum_covers_operations(self):
        """Audit actions should cover all major operations."""
        from openlabels.server.models import AuditActionEnum

        actions = set(AuditActionEnum.enums)

        # Should have scan-related actions
        assert 'scan_started' in actions
        assert 'scan_completed' in actions
        assert 'scan_failed' in actions

        # Should have label actions
        assert 'label_applied' in actions
        assert 'label_removed' in actions

        # Should have remediation actions
        assert 'quarantine_executed' in actions
        assert 'lockdown_executed' in actions

    def test_audit_requires_action(self):
        """Audit log must have an action."""
        from openlabels.server.models import AuditLog

        assert AuditLog.__table__.c.action.nullable is False

    def test_audit_has_timestamp(self):
        """Audit entries must have timestamps."""
        from openlabels.server.models import AuditLog

        created_at = AuditLog.__table__.c.created_at
        assert created_at.server_default is not None


class TestSessionModel:
    """Tests for Session model."""

    def test_session_id_is_string(self):
        """Session ID should be a secure token string."""
        from openlabels.server.models import Session
        from sqlalchemy import String

        id_col = Session.__table__.c.id
        assert isinstance(id_col.type, String)

    def test_session_requires_expiry(self):
        """Sessions must have an expiration time."""
        from openlabels.server.models import Session

        assert Session.__table__.c.expires_at.nullable is False

    def test_session_has_expiry_index(self):
        """Should have index on expires_at for cleanup queries."""
        from openlabels.server.models import Session

        indexes = list(Session.__table__.indexes)
        expiry_indexes = [idx for idx in indexes if 'expires' in idx.name]
        assert len(expiry_indexes) > 0


class TestRemediationModels:
    """Tests for remediation-related models."""

    def test_remediation_action_types(self):
        """Remediation actions should include quarantine and lockdown."""
        from openlabels.server.models import RemediationActionTypeEnum

        actions = set(RemediationActionTypeEnum.enums)
        assert 'quarantine' in actions
        assert 'lockdown' in actions
        assert 'rollback' in actions

    def test_remediation_status_values(self):
        """Remediation status should track lifecycle."""
        from openlabels.server.models import RemediationStatusEnum

        statuses = set(RemediationStatusEnum.enums)
        expected = {'pending', 'completed', 'failed', 'rolled_back'}
        assert statuses == expected

    def test_remediation_tracks_original_acl(self):
        """Remediation should store ACL for rollback."""
        from openlabels.server.models import RemediationAction

        assert 'previous_acl' in RemediationAction.__table__.c


class TestUUIDGeneration:
    """Tests for UUID generation."""

    def test_generate_uuid_returns_uuid(self):
        """generate_uuid should return a valid UUID."""
        from openlabels.server.models import generate_uuid

        result = generate_uuid()
        assert isinstance(result, UUID)

    def test_generate_uuid_is_unique(self):
        """Each call should generate a unique UUID."""
        from openlabels.server.models import generate_uuid

        uuids = [generate_uuid() for _ in range(100)]
        unique_uuids = set(uuids)
        assert len(unique_uuids) == 100
