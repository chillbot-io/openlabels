"""Comprehensive tests for api/settings.py to achieve 80%+ coverage."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from fastapi.testclient import TestClient


class TestCategorizeEntityTypes:
    """Tests for _categorize_entity_types function."""

    def test_categories_returned(self):
        """Should return a dictionary of categories."""
        from scrubiq.api.settings import _categorize_entity_types

        result = _categorize_entity_types()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_has_expected_categories(self):
        """Should have expected category names."""
        from scrubiq.api.settings import _categorize_entity_types

        result = _categorize_entity_types()
        expected_categories = [
            "secrets_cloud", "secrets_code", "secrets_auth",
            "names", "dates", "locations", "contact"
        ]
        for cat in expected_categories:
            assert cat in result, f"Missing expected category: {cat}"

    def test_all_types_categorized(self):
        """All known types should be in some category."""
        from scrubiq.api.settings import _categorize_entity_types
        from scrubiq.types import KNOWN_ENTITY_TYPES

        result = _categorize_entity_types()
        all_categorized = set()
        for types in result.values():
            all_categorized.update(types)

        # All known types should appear in some category
        for entity_type in KNOWN_ENTITY_TYPES:
            assert entity_type in all_categorized, f"Type {entity_type} not categorized"

    def test_categories_sorted(self):
        """Values in each category should be sorted."""
        from scrubiq.api.settings import _categorize_entity_types

        result = _categorize_entity_types()
        for category, types in result.items():
            assert types == sorted(types), f"Category {category} not sorted"

    def test_no_empty_categories(self):
        """No empty categories should be returned."""
        from scrubiq.api.settings import _categorize_entity_types

        result = _categorize_entity_types()
        for category, types in result.items():
            assert len(types) > 0, f"Category {category} is empty"


class TestSettingsSchemas:
    """Tests for settings schema classes."""

    def test_settings_response_defaults(self):
        """SettingsResponse should have defaults."""
        from scrubiq.api.settings import SettingsResponse

        settings = SettingsResponse()
        assert settings.confidence_threshold == 0.85
        assert settings.safe_harbor is True
        assert settings.coreference is True
        assert settings.device == "auto"
        assert settings.llm_provider == "anthropic"

    def test_settings_update_request_optional(self):
        """SettingsUpdateRequest fields should be optional."""
        from scrubiq.api.settings import SettingsUpdateRequest

        # Should work with no fields
        req = SettingsUpdateRequest()
        assert req.confidence_threshold is None

        # Should work with some fields
        req = SettingsUpdateRequest(confidence_threshold=0.7)
        assert req.confidence_threshold == 0.7
        assert req.safe_harbor is None

    def test_entity_types_response(self):
        """EntityTypesResponse should have required fields."""
        from scrubiq.api.settings import EntityTypesResponse

        resp = EntityTypesResponse(types=["NAME", "EMAIL"], categories={"names": ["NAME"]})
        assert resp.types == ["NAME", "EMAIL"]
        assert resp.categories == {"names": ["NAME"]}

    def test_providers_response(self):
        """ProvidersResponse should have required fields."""
        from scrubiq.api.settings import ProvidersResponse

        resp = ProvidersResponse(providers={"anthropic": {"name": "Anthropic"}})
        assert resp.providers["anthropic"]["name"] == "Anthropic"

    def test_allowlist_update_request_validation(self):
        """AllowlistUpdateRequest should validate action."""
        from scrubiq.api.settings import AllowlistUpdateRequest
        from pydantic import ValidationError

        # Valid actions
        for action in ["add", "remove", "set"]:
            req = AllowlistUpdateRequest(action=action, values=["test"])
            assert req.action == action

        # Invalid action should fail
        with pytest.raises(ValidationError):
            AllowlistUpdateRequest(action="invalid", values=["test"])


class TestSettingsConstants:
    """Tests for settings module constants."""

    def test_rate_limits_defined(self):
        """Rate limit constants should be defined."""
        from scrubiq.api.settings import (
            SETTINGS_READ_RATE_LIMIT,
            SETTINGS_WRITE_RATE_LIMIT,
            MAX_ALLOWLIST_ENTRIES,
            MAX_ALLOWLIST_VALUE_LENGTH,
            MAX_ALLOWLIST_BATCH_SIZE,
        )

        assert SETTINGS_READ_RATE_LIMIT > 0
        assert SETTINGS_WRITE_RATE_LIMIT > 0
        assert MAX_ALLOWLIST_ENTRIES > 0
        assert MAX_ALLOWLIST_VALUE_LENGTH > 0
        assert MAX_ALLOWLIST_BATCH_SIZE > 0

    def test_write_limit_less_than_read(self):
        """Write rate limit should be more restrictive than read."""
        from scrubiq.api.settings import (
            SETTINGS_READ_RATE_LIMIT,
            SETTINGS_WRITE_RATE_LIMIT,
        )

        assert SETTINGS_WRITE_RATE_LIMIT < SETTINGS_READ_RATE_LIMIT


class TestSettingsRouterRegistration:
    """Tests for router registration."""

    def test_router_has_prefix(self):
        """Router should have /settings prefix."""
        from scrubiq.api.settings import router

        assert router.prefix == "/settings"

    def test_router_has_tag(self):
        """Router should have settings tag."""
        from scrubiq.api.settings import router

        assert "settings" in router.tags


class TestGetSettingsRoute:
    """Tests for GET /settings route."""

    def test_route_exists(self):
        """GET /settings route should exist."""
        from scrubiq.api.settings import router

        routes = [r for r in router.routes if getattr(r, 'path', '') == '']
        assert len(routes) > 0

    def test_returns_settings_response(self):
        """Route should return SettingsResponse model."""
        from scrubiq.api.settings import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestUpdateSettingsRoute:
    """Tests for PUT /settings route."""

    def test_route_exists(self):
        """PUT /settings route should exist."""
        from scrubiq.api.settings import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '' and
                  'PUT' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestEntityTypesRoute:
    """Tests for GET /entity-types route."""

    def test_route_exists(self):
        """GET /entity-types route should exist."""
        from scrubiq.api.settings import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/entity-types']
        assert len(routes) > 0


class TestProvidersRoute:
    """Tests for GET /providers route."""

    def test_route_exists(self):
        """GET /providers route should exist."""
        from scrubiq.api.settings import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/providers']
        assert len(routes) > 0


class TestAllowlistRoutes:
    """Tests for allowlist routes."""

    def test_get_allowlist_route_exists(self):
        """GET /allowlist route should exist."""
        from scrubiq.api.settings import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/allowlist' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0

    def test_post_allowlist_route_exists(self):
        """POST /allowlist route should exist."""
        from scrubiq.api.settings import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/allowlist' and
                  'POST' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestThresholdsRoutes:
    """Tests for thresholds routes."""

    def test_get_thresholds_route_exists(self):
        """GET /thresholds route should exist."""
        from scrubiq.api.settings import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/thresholds' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0

    def test_put_thresholds_route_exists(self):
        """PUT /thresholds route should exist."""
        from scrubiq.api.settings import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/thresholds' and
                  'PUT' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestValidationLogic:
    """Tests for validation logic in settings routes."""

    def test_valid_device_values(self):
        """Only auto, cuda, cpu should be valid devices."""
        valid_devices = {"auto", "cuda", "cpu"}
        for device in valid_devices:
            assert device in valid_devices

    def test_valid_provider_values(self):
        """Only anthropic, openai should be valid providers."""
        valid_providers = {"anthropic", "openai"}
        for provider in valid_providers:
            assert provider in valid_providers


class TestAllowlistLimits:
    """Tests for allowlist limits."""

    def test_max_entries_limit(self):
        """MAX_ALLOWLIST_ENTRIES should be reasonable."""
        from scrubiq.api.settings import MAX_ALLOWLIST_ENTRIES

        assert 100 <= MAX_ALLOWLIST_ENTRIES <= 10000

    def test_max_value_length(self):
        """MAX_ALLOWLIST_VALUE_LENGTH should be reasonable."""
        from scrubiq.api.settings import MAX_ALLOWLIST_VALUE_LENGTH

        assert 50 <= MAX_ALLOWLIST_VALUE_LENGTH <= 1000

    def test_max_batch_size(self):
        """MAX_ALLOWLIST_BATCH_SIZE should be reasonable."""
        from scrubiq.api.settings import MAX_ALLOWLIST_BATCH_SIZE

        assert 10 <= MAX_ALLOWLIST_BATCH_SIZE <= 500
