"""OpenLabels server middleware."""

from openlabels.server.middleware.csrf import CSRFMiddleware
from openlabels.server.middleware.stack import register_middleware

__all__ = ["CSRFMiddleware", "register_middleware"]
