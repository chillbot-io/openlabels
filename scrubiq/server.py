#!/usr/bin/env python
"""
ScrubIQ Server - Headless API Server.

Run as standalone server without Tauri desktop wrapper.
Supports multi-client concurrent access.

Usage:
    scrubiq-server                    # Default: localhost:8741
    scrubiq-server --host 0.0.0.0     # Bind to all interfaces
    scrubiq-server --port 8080        # Custom port
    scrubiq-server --workers 4        # Multiple workers

Environment variables:
    SCRUBIQ_HOST     - Bind host (default: 127.0.0.1)
    SCRUBIQ_PORT     - Bind port (default: 8741)
    SCRUBIQ_WORKERS  - Number of workers (default: 1)
    SCRUBIQ_DEVICE   - Device for inference: auto, cuda, cpu
    SCRUBIQ_THRESHOLD - Default confidence threshold (0.85)
    PROD=1                  - Enable production mode (disable docs)
    CORS_ORIGINS            - Comma-separated allowed origins
"""

import argparse
import logging
import os
import sys

logger = logging.getLogger(__name__)


def get_env_int(key: str, default: int) -> int:
    """Get integer from environment variable."""
    val = os.environ.get(key)
    if val:
        try:
            return int(val)
        except ValueError:
            pass
    return default


def get_env_str(key: str, default: str) -> str:
    """Get string from environment variable."""
    return os.environ.get(key, default)


def configure_logging(verbose: bool = False, json_logs: bool = False) -> None:
    """Configure logging for server mode."""
    level = logging.DEBUG if verbose else logging.INFO
    
    if json_logs:
        # JSON logging for production/structured logging
        try:
            import json
            
            class JSONFormatter(logging.Formatter):
                def format(self, record):
                    log_obj = {
                        "timestamp": self.formatTime(record),
                        "level": record.levelname,
                        "logger": record.name,
                        "message": record.getMessage(),
                    }
                    if record.exc_info:
                        log_obj["exception"] = self.formatException(record.exc_info)
                    return json.dumps(log_obj)
            
            handler = logging.StreamHandler()
            handler.setFormatter(JSONFormatter())
            logging.root.handlers = [handler]
            logging.root.setLevel(level)
        except Exception:
            logging.basicConfig(level=level)
    else:
        # Standard logging
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    
    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def run_server(
    host: str = "127.0.0.1",
    port: int = 8741,
    workers: int = 1,
    reload: bool = False,
    verbose: bool = False,
    json_logs: bool = False,
) -> None:
    """
    Run the ScrubIQ API server.
    
    Args:
        host: Bind host
        port: Bind port
        workers: Number of worker processes
        reload: Enable auto-reload (dev mode)
        verbose: Enable debug logging
        json_logs: Output logs as JSON
    """
    import uvicorn
    
    configure_logging(verbose=verbose, json_logs=json_logs)
    
    logger.info(f"Starting ScrubIQ Server v{get_version()}")
    logger.info(f"Binding to {host}:{port} with {workers} worker(s)")
    
    if workers > 1:
        logger.info(f"Memory estimate: ~{workers * 2}GB (2GB per worker)")
    
    # Determine device
    device = get_env_str("SCRUBIQ_DEVICE", "auto")
    if device == "auto":
        try:
            import onnxruntime as ort
            device = "cuda" if 'CUDAExecutionProvider' in ort.get_available_providers() else "cpu"
        except ImportError:
            device = "cpu"
    logger.info(f"Inference device: {device}")
    
    # Run server
    uvicorn.run(
        "scrubiq.api.app:app",
        host=host,
        port=port,
        workers=workers,
        reload=reload,
        log_level="debug" if verbose else "info",
        access_log=verbose,
    )


def get_version() -> str:
    """Get package version."""
    try:
        from . import __version__
        return __version__
    except ImportError:
        return "unknown"


def main() -> None:
    """CLI entry point for scrubiq-server."""
    parser = argparse.ArgumentParser(
        prog="scrubiq-server",
        description="ScrubIQ - Headless API Server for PHI/PII Redaction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  scrubiq-server                     Start with defaults
  scrubiq-server --host 0.0.0.0      Bind to all interfaces
  scrubiq-server --workers 4         Run with 4 workers
  scrubiq-server --reload            Development mode with auto-reload

Environment Variables:
  SCRUBIQ_HOST       Bind host (default: 127.0.0.1)
  SCRUBIQ_PORT       Bind port (default: 8741)
  SCRUBIQ_WORKERS    Number of workers (default: 1)
  SCRUBIQ_DEVICE     Inference device: auto, cuda, cpu
  SCRUBIQ_THRESHOLD  Confidence threshold (default: 0.85)
  PROD=1                    Production mode (disables /docs)
  CORS_ORIGINS              Comma-separated allowed origins
        """,
    )
    
    parser.add_argument(
        "--host", "-H",
        default=get_env_str("SCRUBIQ_HOST", "127.0.0.1"),
        help="Host to bind (default: 127.0.0.1, use 0.0.0.0 for all interfaces)",
    )
    
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=get_env_int("SCRUBIQ_PORT", 8741),
        help="Port to bind (default: 8741)",
    )
    
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=get_env_int("SCRUBIQ_WORKERS", 1),
        help="Number of worker processes (default: 1). Each worker uses ~2GB RAM.",
    )
    
    parser.add_argument(
        "--reload", "-r",
        action="store_true",
        help="Enable auto-reload for development",
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    
    parser.add_argument(
        "--json-logs",
        action="store_true",
        help="Output logs as JSON (for structured logging)",
    )
    
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"scrubiq-server {get_version()}",
    )
    
    args = parser.parse_args()
    
    # Validate workers
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    
    if args.workers > 1 and args.reload:
        parser.error("Cannot use --reload with multiple workers")
    
    try:
        run_server(
            host=args.host,
            port=args.port,
            workers=args.workers,
            reload=args.reload,
            verbose=args.verbose,
            json_logs=args.json_logs,
        )
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
