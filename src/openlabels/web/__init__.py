"""
Web UI module for OpenLabels.

Provides a browser-based admin console using:
- FastAPI for routing
- Jinja2 for templating
- HTMX for dynamic updates without full page reloads
- Alpine.js for client-side interactivity
- Tailwind CSS for styling
"""

from openlabels.web.routes import router

__all__ = ["router"]
