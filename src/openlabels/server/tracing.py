"""Optional OpenTelemetry distributed tracing setup.

Enable tracing by setting ``tracing.enabled = true`` in config and installing
the ``tracing`` optional dependency group::

    pip install openlabels[tracing]

When disabled (the default), this module is a no-op.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import FastAPI

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TracingSettings:
    """Tracing configuration — typically read from the app ``Settings``."""

    enabled: bool = False
    otlp_endpoint: str = "http://localhost:4317"
    service_name: str = "openlabels-api"


def setup_tracing(app: FastAPI, *, settings: TracingSettings | None = None) -> bool:
    """Initialise OpenTelemetry tracing if enabled.

    Returns ``True`` when tracing was successfully configured, ``False`` otherwise.
    """
    if settings is None:
        settings = TracingSettings()

    if not settings.enabled:
        logger.debug("OpenTelemetry tracing disabled")
        return False

    try:
        from opentelemetry import trace  # type: ignore[import-not-found]
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore[import-not-found]
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.fastapi import (
            FastAPIInstrumentor,  # type: ignore[import-not-found]
        )
        from opentelemetry.sdk.resources import Resource  # type: ignore[import-not-found]
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-not-found]
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,  # type: ignore[import-not-found]
        )
    except ImportError:
        logger.warning(
            "opentelemetry packages not installed — tracing disabled. "
            "Install with: pip install openlabels[tracing]"
        )
        return False

    try:
        from openlabels import __version__

        provider = TracerProvider(
            resource=Resource.create(
                {
                    "service.name": settings.service_name,
                    "service.version": __version__,
                }
            ),
        )

        exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        # Auto-instrument FastAPI
        FastAPIInstrumentor.instrument_app(app)

        # Optionally instrument SQLAlchemy if available
        try:
            from opentelemetry.instrumentation.sqlalchemy import (  # type: ignore[import-not-found]
                SQLAlchemyInstrumentor,
            )
            SQLAlchemyInstrumentor().instrument()
        except ImportError:
            pass

        # Optionally instrument HTTPX if available
        try:
            from opentelemetry.instrumentation.httpx import (
                HTTPXClientInstrumentor,  # type: ignore[import-not-found]
            )
            HTTPXClientInstrumentor().instrument()
        except ImportError:
            pass

        logger.info(
            f"OpenTelemetry tracing enabled "
            f"(service={settings.service_name}, endpoint={settings.otlp_endpoint})"
        )
        return True

    except Exception as e:
        logger.error(f"Failed to initialize OpenTelemetry: {e}")
        return False
