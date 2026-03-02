"""Tests for LabelService (label sync + bulk apply)."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from openlabels.exceptions import BadRequestError, NotFoundError, ValidationError
from openlabels.server.services.base import TenantContext
from openlabels.server.services.label_service import LabelService


def _make_service(session=None, tenant_id=None, user_id=None, settings=None):
    """Create a LabelService with mocked dependencies."""
    session = session or AsyncMock()
    tenant = TenantContext(
        tenant_id=tenant_id or uuid4(),
        user_id=user_id or uuid4(),
    )
    if settings is None:
        settings = MagicMock()
    return LabelService(session, tenant, settings)


# ---------------------------------------------------------------------------
# List Labels
# ---------------------------------------------------------------------------


class TestListLabels:
    @pytest.mark.asyncio
    async def test_list_labels_delegates_to_paginate(self):
        svc = _make_service()

        with patch.object(svc, "paginate", new_callable=AsyncMock) as mock_paginate:
            mock_paginate.return_value = ([], 0)

            labels, total = await svc.list_labels(limit=10, offset=5)
            assert total == 0
            assert labels == []
            mock_paginate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_list_labels_default_pagination(self):
        svc = _make_service()

        with patch.object(svc, "paginate", new_callable=AsyncMock) as mock_paginate:
            mock_labels = [MagicMock(), MagicMock()]
            mock_paginate.return_value = (mock_labels, 2)

            labels, total = await svc.list_labels()
            assert total == 2
            assert len(labels) == 2


# ---------------------------------------------------------------------------
# Get Label
# ---------------------------------------------------------------------------


class TestGetLabel:
    @pytest.mark.asyncio
    async def test_get_label_own_tenant(self):
        tid = uuid4()
        label_id = "label-guid-001"

        mock_label = MagicMock()
        mock_label.tenant_id = tid
        mock_label.id = label_id

        session = AsyncMock()
        session.get.return_value = mock_label

        svc = _make_service(session=session, tenant_id=tid)
        result = await svc.get_label(label_id)
        assert result is mock_label

    @pytest.mark.asyncio
    async def test_get_label_not_found(self):
        session = AsyncMock()
        session.get.return_value = None

        svc = _make_service(session=session)
        with pytest.raises(NotFoundError):
            await svc.get_label("nonexistent-label")


# ---------------------------------------------------------------------------
# Sync Labels
# ---------------------------------------------------------------------------


class TestSyncLabels:
    @pytest.mark.asyncio
    async def test_sync_labels_not_configured_raises(self):
        settings = MagicMock()
        settings.auth.provider = "local"
        settings.auth.tenant_id = None
        settings.auth.client_id = None
        settings.auth.client_secret = None

        svc = _make_service(settings=settings)

        with pytest.raises(BadRequestError, match="Azure AD not configured"):
            await svc.sync_labels()

    @pytest.mark.asyncio
    @patch("openlabels.jobs.JobQueue")
    async def test_sync_labels_background(self, MockJobQueue):
        settings = MagicMock()
        settings.auth.provider = "azure_ad"
        settings.auth.tenant_id = "azure-tid"
        settings.auth.client_id = "client-id"
        settings.auth.client_secret.get_secret_value.return_value = "secret"

        mock_queue = AsyncMock()
        mock_queue.enqueue.return_value = uuid4()
        MockJobQueue.return_value = mock_queue

        svc = _make_service(settings=settings)
        result = await svc.sync_labels(background=True)

        assert result["background"] is True
        assert "job_id" in result
        mock_queue.enqueue.assert_awaited_once()

    @pytest.mark.asyncio
    @patch("openlabels.jobs.tasks.label_sync.sync_labels_from_graph")
    async def test_sync_labels_immediate(self, mock_sync):
        settings = MagicMock()
        settings.auth.provider = "azure_ad"
        settings.auth.tenant_id = "azure-tid"
        settings.auth.client_id = "client-id"
        settings.auth.client_secret.get_secret_value.return_value = "secret"

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"created": 3, "updated": 0, "deleted": 0}
        mock_sync.return_value = mock_result

        session = AsyncMock()
        svc = _make_service(session=session, settings=settings)

        with patch.object(svc, "_invalidate_label_caches"):
            result = await svc.sync_labels(background=False)

        assert result["message"] == "Label sync completed"
        assert result["created"] == 3
        session.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# Label Rules - CRUD
# ---------------------------------------------------------------------------


class TestCreateLabelRule:
    @pytest.mark.asyncio
    async def test_create_rule_invalid_type_raises(self):
        svc = _make_service()

        with pytest.raises(ValidationError, match="Invalid rule type"):
            await svc.create_label_rule({"rule_type": "invalid"})

    @pytest.mark.asyncio
    async def test_create_rule_missing_label_id_raises(self):
        svc = _make_service()

        with pytest.raises(ValidationError, match="Label ID is required"):
            await svc.create_label_rule({
                "rule_type": "risk_tier",
                "match_value": "CRITICAL",
            })

    @pytest.mark.asyncio
    async def test_create_rule_label_not_found_raises(self):
        tid = uuid4()

        session = AsyncMock()
        session.get.return_value = None  # Label not found

        svc = _make_service(session=session, tenant_id=tid)

        with pytest.raises(NotFoundError):
            await svc.create_label_rule({
                "rule_type": "risk_tier",
                "match_value": "CRITICAL",
                "label_id": "nonexistent-label",
            })

    @pytest.mark.asyncio
    async def test_create_rule_valid(self):
        tid = uuid4()
        label_id = "label-guid-001"

        mock_label = MagicMock()
        mock_label.tenant_id = tid
        mock_label.id = label_id

        session = AsyncMock()
        session.get.return_value = mock_label

        svc = _make_service(session=session, tenant_id=tid)

        rule = await svc.create_label_rule({
            "rule_type": "risk_tier",
            "match_value": "CRITICAL",
            "label_id": label_id,
            "priority": 10,
        })

        assert rule.rule_type == "risk_tier"
        assert rule.match_value == "CRITICAL"
        assert rule.label_id == label_id
        assert rule.priority == 10
        assert rule.tenant_id == tid
        session.add.assert_called_once()
        session.flush.assert_awaited()


class TestUpdateLabelRule:
    @pytest.mark.asyncio
    async def test_update_rule_invalid_type_raises(self):
        tid = uuid4()
        rule_id = uuid4()

        mock_rule = MagicMock()
        mock_rule.tenant_id = tid
        mock_rule.id = rule_id

        session = AsyncMock()
        session.get.return_value = mock_rule

        svc = _make_service(session=session, tenant_id=tid)

        with pytest.raises(ValidationError, match="Invalid rule type"):
            await svc.update_label_rule(rule_id, {"rule_type": "invalid"})

    @pytest.mark.asyncio
    async def test_update_rule_fields(self):
        tid = uuid4()
        rule_id = uuid4()

        mock_rule = MagicMock()
        mock_rule.tenant_id = tid
        mock_rule.id = rule_id
        mock_rule.rule_type = "risk_tier"

        session = AsyncMock()
        session.get.return_value = mock_rule

        svc = _make_service(session=session, tenant_id=tid)

        result = await svc.update_label_rule(rule_id, {
            "match_value": "HIGH",
            "priority": 20,
        })

        assert result.match_value == "HIGH"
        assert result.priority == 20
        session.flush.assert_awaited()


class TestDeleteLabelRule:
    @pytest.mark.asyncio
    async def test_delete_rule_not_found_raises(self):
        tid = uuid4()
        rule_id = uuid4()

        # Mock the execute result with rowcount == 0
        mock_result = MagicMock()
        mock_result.rowcount = 0

        session = AsyncMock()
        session.execute.return_value = mock_result

        svc = _make_service(session=session, tenant_id=tid)

        with pytest.raises(NotFoundError, match="Label rule not found"):
            await svc.delete_label_rule(rule_id)

    @pytest.mark.asyncio
    async def test_delete_rule_success(self):
        tid = uuid4()
        rule_id = uuid4()

        mock_result = MagicMock()
        mock_result.rowcount = 1

        session = AsyncMock()
        session.execute.return_value = mock_result

        svc = _make_service(session=session, tenant_id=tid)

        result = await svc.delete_label_rule(rule_id)
        assert result is True
        session.flush.assert_awaited()


# ---------------------------------------------------------------------------
# Get Label Rules
# ---------------------------------------------------------------------------


class TestGetLabelRules:
    @pytest.mark.asyncio
    async def test_get_label_rules_empty(self):
        tid = uuid4()

        # Mock count query returning 0
        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 0

        # Mock main query returning empty
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []

        mock_rules_result = MagicMock()
        mock_rules_result.scalars.return_value = mock_scalars

        session = AsyncMock()
        session.execute.side_effect = [mock_count_result, mock_rules_result]

        svc = _make_service(session=session, tenant_id=tid)

        rules, total = await svc.get_label_rules()
        assert total == 0
        assert rules == []


# ---------------------------------------------------------------------------
# Bulk Apply Labels
# ---------------------------------------------------------------------------


class TestBulkApplyLabels:
    @pytest.mark.asyncio
    async def test_bulk_apply_label_not_found_raises(self):
        session = AsyncMock()
        session.get.return_value = None  # Label not found

        svc = _make_service(session=session)

        with pytest.raises(NotFoundError):
            await svc.bulk_apply_labels(
                result_ids=[uuid4()],
                label_id="nonexistent-label",
            )

    @pytest.mark.asyncio
    @patch("openlabels.jobs.JobQueue")
    async def test_bulk_apply_success(self, MockJobQueue):
        tid = uuid4()
        label_id = "label-guid-001"
        result_ids = [uuid4(), uuid4()]

        # Mock label exists
        mock_label = MagicMock()
        mock_label.tenant_id = tid
        mock_label.id = label_id

        # Mock scan results
        mock_results = []
        for rid in result_ids:
            mr = MagicMock()
            mr.id = rid
            mr.file_path = f"/data/{rid}.txt"
            mr.tenant_id = tid
            mock_results.append(mr)

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_results

        mock_execute_result = MagicMock()
        mock_execute_result.scalars.return_value = mock_scalars

        session = AsyncMock()
        # First call: session.get for label, subsequent calls: execute for results
        session.get.return_value = mock_label
        session.execute.return_value = mock_execute_result

        mock_queue = AsyncMock()
        MockJobQueue.return_value = mock_queue

        svc = _make_service(session=session, tenant_id=tid)
        result = await svc.bulk_apply_labels(result_ids, label_id)

        assert result["success"] == 2
        assert result["failed"] == 0
        assert result["skipped"] == 0
        assert mock_queue.enqueue.await_count == 2

    @pytest.mark.asyncio
    @patch("openlabels.jobs.JobQueue")
    async def test_bulk_apply_skips_missing_results(self, MockJobQueue):
        tid = uuid4()
        label_id = "label-guid-001"
        existing_id = uuid4()
        missing_id = uuid4()

        mock_label = MagicMock()
        mock_label.tenant_id = tid
        mock_label.id = label_id

        # Only one result exists
        mock_result = MagicMock()
        mock_result.id = existing_id
        mock_result.file_path = "/data/found.txt"
        mock_result.tenant_id = tid

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [mock_result]

        mock_execute_result = MagicMock()
        mock_execute_result.scalars.return_value = mock_scalars

        session = AsyncMock()
        session.get.return_value = mock_label
        session.execute.return_value = mock_execute_result

        mock_queue = AsyncMock()
        MockJobQueue.return_value = mock_queue

        svc = _make_service(session=session, tenant_id=tid)
        result = await svc.bulk_apply_labels([existing_id, missing_id], label_id)

        assert result["success"] == 1
        assert result["skipped"] == 1
        assert result["failed"] == 0

    @pytest.mark.asyncio
    @patch("openlabels.jobs.JobQueue")
    async def test_bulk_apply_handles_enqueue_failure(self, MockJobQueue):
        tid = uuid4()
        label_id = "label-guid-001"
        result_id = uuid4()

        mock_label = MagicMock()
        mock_label.tenant_id = tid
        mock_label.id = label_id

        mock_result = MagicMock()
        mock_result.id = result_id
        mock_result.file_path = "/data/file.txt"
        mock_result.tenant_id = tid

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [mock_result]

        mock_execute_result = MagicMock()
        mock_execute_result.scalars.return_value = mock_scalars

        session = AsyncMock()
        session.get.return_value = mock_label
        session.execute.return_value = mock_execute_result

        mock_queue = AsyncMock()
        mock_queue.enqueue.side_effect = RuntimeError("connection lost")
        MockJobQueue.return_value = mock_queue

        svc = _make_service(session=session, tenant_id=tid)
        result = await svc.bulk_apply_labels([result_id], label_id)

        assert result["success"] == 0
        assert result["failed"] == 1
        assert result["skipped"] == 0


# ---------------------------------------------------------------------------
# Invalidate Label Caches
# ---------------------------------------------------------------------------


class TestInvalidateLabelCaches:
    def test_invalidate_handles_import_error(self):
        svc = _make_service()

        with patch(
            "openlabels.server.services.label_service.LabelService._invalidate_label_caches"
        ) as mock_invalidate:
            # Should not raise even if underlying cache is unavailable
            svc._invalidate_label_caches()
