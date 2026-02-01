"""
OpenLabels Scanner API.

Provides an async REST API and WebSocket interface for file scanning.

Usage:
    # Start the server
    openlabels serve --port 8000

    # Or programmatically
    from openlabels.api.server import run_server
    run_server(port=8000)

Requires: pip install 'openlabels[server]' or pip install fastapi uvicorn
"""

__all__ = [
    "run_server",
]


def run_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """Run the scanner API server.

    Args:
        host: Host to bind to (default: 0.0.0.0)
        port: Port to bind to (default: 8000)
        reload: Enable auto-reload for development
    """
    from .server import run_server as _run_server
    _run_server(host=host, port=port, reload=reload)
