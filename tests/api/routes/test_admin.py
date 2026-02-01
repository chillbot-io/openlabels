"""Comprehensive tests for api/routes/admin.py to achieve 80%+ coverage."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import date


class TestAdminConstants:
    """Tests for admin module constants."""

    def test_admin_rate_limit_defined(self):
        """ADMIN_READ_RATE_LIMIT should be defined."""
        from scrubiq.api.routes.admin import ADMIN_READ_RATE_LIMIT

        assert ADMIN_READ_RATE_LIMIT > 0

    def test_greeting_rate_limit_defined(self):
        """GREETING_RATE_LIMIT should be defined."""
        from scrubiq.api.routes.admin import GREETING_RATE_LIMIT

        assert GREETING_RATE_LIMIT > 0

    def test_greeting_more_restricted(self):
        """Greeting rate limit should be more restrictive."""
        from scrubiq.api.routes.admin import ADMIN_READ_RATE_LIMIT, GREETING_RATE_LIMIT

        assert GREETING_RATE_LIMIT <= ADMIN_READ_RATE_LIMIT

    def test_is_production_flag(self):
        """_IS_PRODUCTION flag should be boolean."""
        from scrubiq.api.routes.admin import _IS_PRODUCTION

        assert isinstance(_IS_PRODUCTION, bool)


class TestGreetingCache:
    """Tests for greeting cache mechanism."""

    def test_greeting_cache_structure(self):
        """Greeting cache should have date and greeting keys."""
        from scrubiq.api.routes.admin import _greeting_cache

        assert "date" in _greeting_cache
        assert "greeting" in _greeting_cache


class TestAdminRouterRegistration:
    """Tests for admin router configuration."""

    def test_router_has_tag(self):
        """Router should have admin tag."""
        from scrubiq.api.routes.admin import router

        assert "admin" in router.tags

    def test_router_routes_exist(self):
        """Router should have expected routes."""
        from scrubiq.api.routes.admin import router

        paths = [getattr(r, 'path', '') for r in router.routes]
        assert '/health' in paths
        assert '/health/detailed' in paths
        assert '/greeting' in paths
        assert '/audit/status' in paths


class TestHealthRoute:
    """Tests for GET /health route."""

    def test_route_exists(self):
        """GET /health route should exist."""
        from scrubiq.api.routes.admin import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/health' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0

    def test_health_function_returns_status(self):
        """health() function should return status ok."""
        from scrubiq.api.routes.admin import health

        result = health()
        assert result == {"status": "ok"}


class TestSecurityTxtRoute:
    """Tests for GET /.well-known/security.txt route."""

    def test_route_exists(self):
        """GET /.well-known/security.txt route should exist."""
        from scrubiq.api.routes.admin import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/.well-known/security.txt' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0

    def test_security_txt_content(self):
        """security_txt() should return security policy text."""
        from scrubiq.api.routes.admin import security_txt

        result = security_txt()
        assert "ScrubIQ Security Policy" in result
        assert "Contact:" in result
        assert "github.com" in result
        assert "RFC 9116" in result


class TestHealthDetailedRoute:
    """Tests for GET /health/detailed route."""

    def test_route_exists(self):
        """GET /health/detailed route should exist."""
        from scrubiq.api.routes.admin import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/health/detailed' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestGreetingRoute:
    """Tests for GET /greeting route."""

    def test_route_exists(self):
        """GET /greeting route should exist."""
        from scrubiq.api.routes.admin import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/greeting' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestAuditStatusRoute:
    """Tests for GET /audit/status route."""

    def test_route_exists(self):
        """GET /audit/status route should exist."""
        from scrubiq.api.routes.admin import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/audit/status' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestGreetingResponseSchema:
    """Tests for GreetingResponse schema."""

    def test_schema_exists(self):
        """GreetingResponse schema should exist."""
        from scrubiq.api.routes.schemas import GreetingResponse

        assert GreetingResponse is not None

    def test_schema_fields(self):
        """GreetingResponse should have required fields."""
        from scrubiq.api.routes.schemas import GreetingResponse

        resp = GreetingResponse(greeting="Hello!", cached=False)
        assert resp.greeting == "Hello!"
        assert resp.cached is False


class TestLimiterConfiguration:
    """Tests for rate limiter configuration."""

    def test_slowapi_available_flag(self):
        """SLOWAPI_AVAILABLE should be boolean."""
        from scrubiq.api.routes.admin import SLOWAPI_AVAILABLE

        assert isinstance(SLOWAPI_AVAILABLE, bool)
