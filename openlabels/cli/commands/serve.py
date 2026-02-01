"""
OpenLabels Scanner Server command.

Start the async scanning API server.

Usage:
    openlabels serve
    openlabels serve --port 8080
    openlabels serve --host 127.0.0.1 --port 8000
"""

from openlabels.cli.output import info, error


def cmd_serve(args) -> int:
    """Start the OpenLabels Scanner API server."""
    try:
        import uvicorn
    except ImportError:
        error("uvicorn is required for the API server.")
        error("Install it with: pip install 'openlabels[server]'")
        error("Or: pip install uvicorn fastapi")
        return 1

    try:
        from openlabels.api.server import app
    except ImportError as e:
        if "fastapi" in str(e).lower():
            error("FastAPI is required for the API server.")
            error("Install it with: pip install 'openlabels[server]'")
            error("Or: pip install uvicorn fastapi")
            return 1
        raise

    host = getattr(args, "host", "0.0.0.0")
    port = getattr(args, "port", 8000)
    reload = getattr(args, "reload", False)

    info(f"Starting OpenLabels Scanner API on http://{host}:{port}")
    info("API docs available at: http://{host}:{port}/docs")
    info("")
    info("Endpoints:")
    info("  POST /scan          - Start a new scan")
    info("  GET  /scan/{id}     - Get scan status")
    info("  GET  /scan/{id}/results - Get results")
    info("  GET  /scan/{id}/events  - Stream events (SSE)")
    info("  WS   /scan/{id}/ws      - WebSocket events")
    info("")

    uvicorn.run(
        "openlabels.api.server:app",
        host=host,
        port=port,
        reload=reload,
    )

    return 0


def add_serve_parser(subparsers):
    """Add the serve subparser."""
    parser = subparsers.add_parser(
        "serve",
        help="Start the scanner API server",
    )
    parser.add_argument(
        "--host", "-H",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8000,
        help="Port to bind to (default: 8000)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    parser.set_defaults(func=cmd_serve)

    return parser
