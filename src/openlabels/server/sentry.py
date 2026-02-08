"""Sentry error tracking initialization."""

from __future__ import annotations

import logging
import re
from typing import Any

from openlabels import __version__
from openlabels.server.config import SentrySettings

logger = logging.getLogger(__name__)


def _scrub_sensitive_data(data: Any, sensitive_fields: list[str]) -> Any:
    """Recursively scrub sensitive data from dictionaries and lists."""
    if isinstance(data, dict):
        return {
            key: "[Filtered]" if any(
                re.search(field, key, re.IGNORECASE) for field in sensitive_fields
            ) else _scrub_sensitive_data(value, sensitive_fields)
            for key, value in data.items()
        }
    elif isinstance(data, list):
        return [_scrub_sensitive_data(item, sensitive_fields) for item in data]
    return data


def _create_before_send_hook(
    sentry_settings: SentrySettings,
) -> Any:
    """Create a Sentry before_send hook that scrubs sensitive data."""
    sensitive_fields = sentry_settings.sensitive_fields

    def before_send(
        event: dict[str, Any], hint: dict[str, Any],
    ) -> dict[str, Any] | None:
        if "request" in event:
            request_data = event["request"]
            for key in ("headers", "cookies", "query_string", "data"):
                if key in request_data:
                    request_data[key] = _scrub_sensitive_data(
                        request_data[key], sensitive_fields,
                    )

        if "extra" in event:
            event["extra"] = _scrub_sensitive_data(event["extra"], sensitive_fields)

        if "breadcrumbs" in event:
            for breadcrumb in event.get("breadcrumbs", {}).get("values", []):
                if "data" in breadcrumb:
                    breadcrumb["data"] = _scrub_sensitive_data(
                        breadcrumb["data"], sensitive_fields,
                    )

        return event

    return before_send


def init_sentry(sentry_settings: SentrySettings, server_environment: str) -> bool:
    """Initialize Sentry error tracking if DSN is configured."""
    if not sentry_settings.dsn:
        logger.info("Sentry DSN not configured, error tracking disabled")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration

        environment = sentry_settings.environment or server_environment
        traces_sample_rate = sentry_settings.traces_sample_rate
        profiles_sample_rate = sentry_settings.profiles_sample_rate

        if server_environment == "development":
            traces_sample_rate = max(traces_sample_rate, 0.5)
            profiles_sample_rate = max(profiles_sample_rate, 0.5)

        sentry_sdk.init(
            dsn=sentry_settings.dsn,
            environment=environment,
            release=f"openlabels@{__version__}",
            traces_sample_rate=traces_sample_rate,
            profiles_sample_rate=profiles_sample_rate,
            before_send=_create_before_send_hook(sentry_settings),
            integrations=[
                FastApiIntegration(transaction_style="endpoint"),
                StarletteIntegration(transaction_style="endpoint"),
                LoggingIntegration(
                    level=logging.INFO,
                    event_level=logging.ERROR,
                ),
            ],
            send_default_pii=False,
            attach_stacktrace=True,
            max_breadcrumbs=50,
        )

        logger.info(
            f"Sentry initialized for environment '{environment}' "
            f"(traces: {traces_sample_rate:.0%}, profiles: {profiles_sample_rate:.0%})"
        )
        return True

    except ImportError:
        logger.warning("sentry-sdk not installed, error tracking disabled")
        return False
    except Exception as e:
        logger.error(f"Failed to initialize Sentry: {e}")
        return False
