"""
Structured logging configuration for OpenLabels.

Provides:
- JSON-formatted logs for production (machine-readable)
- Human-readable logs for development
- Request correlation ID support
- Configurable log levels per module

Usage:
    from openlabels.server.logging import setup_logging, get_logger

    # Setup logging at application startup
    setup_logging()

    # Get a logger for your module
    logger = get_logger(__name__)
    logger.info("Starting scan", extra={"scan_id": "123", "target": "sharepoint"})
"""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

# Context variable for request correlation ID
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    """Get the current request correlation ID."""
    return request_id_var.get()


def set_request_id(request_id: str) -> None:
    """Set the current request correlation ID."""
    request_id_var.set(request_id)


class JSONFormatter(logging.Formatter):
    """
    JSON log formatter for structured logging.

    Output format:
    {
        "timestamp": "2024-01-15T10:30:00.123456Z",
        "level": "INFO",
        "logger": "openlabels.server.routes.scans",
        "message": "Scan started",
        "request_id": "abc123",
        "scan_id": "def456",
        ...
    }
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add request correlation ID if available
        request_id = get_request_id()
        if request_id:
            log_data["request_id"] = request_id

        # Add source location for debug/error logs
        if record.levelno >= logging.WARNING:
            log_data["source"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add any extra fields from the log record
        # Skip standard LogRecord attributes
        skip_attrs = {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "exc_info", "exc_text", "thread", "threadName",
            "taskName", "message",
        }
        for key, value in record.__dict__.items():
            if key not in skip_attrs and not key.startswith("_"):
                try:
                    # Ensure value is JSON serializable
                    json.dumps(value)
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)

        return json.dumps(log_data, default=str)


class DevelopmentFormatter(logging.Formatter):
    """
    Human-readable log formatter for development.

    Output format:
    2024-01-15 10:30:00 INFO [openlabels.server.routes.scans] Scan started scan_id=def456
    """

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def __init__(self, use_colors: bool = True) -> None:
        super().__init__()
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname

        if self.use_colors:
            color = self.COLORS.get(level, "")
            level = f"{color}{level}{self.RESET}"

        # Collect extra fields
        skip_attrs = {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "exc_info", "exc_text", "thread", "threadName",
            "taskName", "message",
        }
        extras = []
        for key, value in record.__dict__.items():
            if key not in skip_attrs and not key.startswith("_"):
                extras.append(f"{key}={value}")

        extra_str = " ".join(extras)
        if extra_str:
            extra_str = " " + extra_str

        # Add request ID if available
        request_id = get_request_id()
        request_str = f" [{request_id[:8]}]" if request_id else ""

        message = f"{timestamp} {level:8}{request_str} [{record.name}] {record.getMessage()}{extra_str}"

        if record.exc_info:
            message += "\n" + self.formatException(record.exc_info)

        return message


def setup_logging(
    level: str = "INFO",
    json_format: bool = False,
    log_file: str | None = None,
) -> None:
    """
    Configure logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        json_format: Use JSON formatting (for production)
        log_file: Optional file path to write logs
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Choose formatter based on mode
    if json_format:
        formatter: logging.Formatter = JSONFormatter()
    else:
        formatter = DevelopmentFormatter(use_colors=sys.stdout.isatty())

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        # Always use JSON for file logs
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


# Convenience functions for logging with extra context
class ContextLogger:
    """
    Logger wrapper that automatically includes context fields.

    Usage:
        logger = ContextLogger(__name__, tenant_id="abc", job_id="123")
        logger.info("Processing file", file_path="/path/to/file")
    """

    def __init__(self, name: str, **context: Any) -> None:
        self._logger = logging.getLogger(name)
        self._context = context

    def _log(self, level: int, msg: str, **kwargs: Any) -> None:
        extra = {**self._context, **kwargs}
        self._logger.log(level, msg, extra=extra)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, **kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, **kwargs)

    def exception(self, msg: str, **kwargs: Any) -> None:
        self._logger.exception(msg, extra={**self._context, **kwargs})
