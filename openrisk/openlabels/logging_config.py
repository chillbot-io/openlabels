"""
OpenLabels logging configuration.

Provides structured JSON logging with correlation IDs and separate audit trail.

Usage:
    from openlabels.logging_config import setup_logging, get_audit_logger, correlation_id

    # In CLI main:
    setup_logging(verbose=True, log_file="/var/log/openlabels.log")

    # Set correlation ID for request tracing:
    with correlation_id("scan-12345"):
        # All logs within this context include the correlation ID
        logger.info("Starting scan")

    # For audit events:
    audit = get_audit_logger()
    audit.file_quarantine(source="/data/file.txt", destination="/quarantine", score=85)
"""

import logging
import json
import sys
import uuid
from contextvars import ContextVar
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any, Generator


# Thread-safe correlation ID storage
_correlation_id: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)


def get_correlation_id() -> Optional[str]:
    """Get the current correlation ID, if set."""
    return _correlation_id.get()


def set_correlation_id(cid: str) -> None:
    """Set the correlation ID for the current context."""
    _correlation_id.set(cid)


def generate_correlation_id() -> str:
    """Generate a new correlation ID."""
    return str(uuid.uuid4())[:12]


@contextmanager
def correlation_id(cid: Optional[str] = None) -> Generator[str, None, None]:
    """
    Context manager for setting correlation ID.

    Args:
        cid: Correlation ID to use. If None, generates a new one.

    Yields:
        The correlation ID being used.

    Example:
        with correlation_id() as cid:
            logger.info("Processing")  # Logs include correlation_id field
            print(f"Request ID: {cid}")
    """
    if cid is None:
        cid = generate_correlation_id()
    token = _correlation_id.set(cid)
    try:
        yield cid
    finally:
        _correlation_id.reset(token)


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Outputs one JSON object per line for easy parsing by log aggregators
    like Elasticsearch, Splunk, or CloudWatch.

    Includes correlation ID when available.
    """

    # Standard LogRecord attributes to exclude from extra fields
    STANDARD_ATTRS = frozenset([
        "name", "msg", "args", "created", "filename", "funcName",
        "levelname", "levelno", "lineno", "module", "msecs",
        "pathname", "process", "processName", "relativeCreated",
        "stack_info", "exc_info", "exc_text", "thread", "threadName",
        "message", "taskName"
    ])

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add correlation ID if present
        cid = get_correlation_id()
        if cid:
            log_data["correlation_id"] = cid

        # Add source location for debug/warning/error
        if record.levelno >= logging.WARNING or record.levelno == logging.DEBUG:
            log_data["source"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add any extra fields passed via the `extra` parameter
        for key, value in record.__dict__.items():
            if key not in self.STANDARD_ATTRS:
                log_data[key] = value

        return json.dumps(log_data, default=str)


# Default audit log location
DEFAULT_AUDIT_LOG = Path.home() / ".openlabels" / "audit.log"


class AuditLogger:
    """
    Structured audit logger for security-relevant operations.

    Audit events are always logged at INFO level with structured data.
    All audit events automatically include correlation ID and timestamp.

    Usage:
        audit = get_audit_logger()
        audit.file_quarantine(source="/data/file.txt", destination="/quarantine", score=85)
        audit.scan_complete(path="/data", files_scanned=100, pii_found=5)
    """

    def __init__(self, logger: logging.Logger):
        self._logger = logger

    def log(self, event: str, **kwargs: Any) -> None:
        """
        Log an audit event with structured data.

        Args:
            event: Event type (e.g., "file_quarantine", "scan_start")
            **kwargs: Additional structured data for the event
        """
        extra = {
            "audit_event": event,
            "audit_data": kwargs,
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        # Correlation ID is added automatically by JSONFormatter
        self._logger.info(f"AUDIT: {event}", extra=extra)

    # Convenience methods for common events
    def scan_start(self, path: str, **kwargs) -> None:
        """Log start of a scan operation."""
        self.log("scan_start", path=path, **kwargs)

    def scan_complete(self, path: str, files_scanned: int, **kwargs) -> None:
        """Log completion of a scan operation."""
        self.log("scan_complete", path=path, files_scanned=files_scanned, **kwargs)

    def file_quarantine(self, source: str, destination: str, score: int, **kwargs) -> None:
        """Log a file quarantine action."""
        self.log("file_quarantine", source=source, destination=destination, score=score, **kwargs)

    def file_encrypt(self, path: str, tool: str, **kwargs) -> None:
        """Log a file encryption action."""
        self.log("file_encrypt", path=path, tool=tool, **kwargs)

    def access_restrict(self, path: str, mode: str, **kwargs) -> None:
        """Log an access restriction action."""
        self.log("access_restrict", path=path, mode=mode, **kwargs)

    def file_tag(self, path: str, label_id: str, **kwargs) -> None:
        """Log a file tagging action."""
        self.log("file_tag", path=path, label_id=label_id, **kwargs)


# Module-level audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        logger = logging.getLogger("audit.openlabels")
        _audit_logger = AuditLogger(logger)
    return _audit_logger


def setup_logging(
    verbose: bool = False,
    quiet: bool = False,
    log_file: Optional[str] = None,
    audit_log: Optional[str] = None,
    no_audit: bool = False,
) -> str:
    """
    Configure logging for the application.

    Args:
        verbose: Enable DEBUG level logging
        quiet: Only show ERROR and above
        log_file: Path to application log file
        audit_log: Path to audit log file (default: ~/.openlabels/audit.log)
        no_audit: Disable audit logging entirely

    Returns:
        The correlation ID generated for this session.

    Examples:
        # Standard usage - JSON to console, audit to default location
        setup_logging()

        # Verbose mode for debugging
        setup_logging(verbose=True)

        # Production with custom log files
        setup_logging(
            log_file="/var/log/openlabels/app.log",
            audit_log="/var/log/openlabels/audit.log"
        )
    """
    # Generate session correlation ID
    session_id = generate_correlation_id()
    set_correlation_id(session_id)

    # Determine log level
    # Default is WARNING (quiet for users), --verbose shows INFO/DEBUG
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING  # Default: only show warnings and errors

    # Get root logger for openlabels
    root_logger = logging.getLogger("openlabels")
    root_logger.setLevel(logging.DEBUG)  # Capture all, filter at handler level
    root_logger.handlers.clear()

    # Console handler (JSON format)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(console_handler)

    # Application log file handler
    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Capture everything to file
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)

    # Setup audit logger
    audit_logger = logging.getLogger("audit.openlabels")
    audit_logger.setLevel(logging.INFO)
    audit_logger.handlers.clear()
    audit_logger.propagate = False  # Don't propagate to root logger

    if not no_audit:
        # Determine audit log path
        audit_path = Path(audit_log) if audit_log else DEFAULT_AUDIT_LOG
        audit_path.parent.mkdir(parents=True, exist_ok=True)

        audit_handler = logging.FileHandler(audit_path)
        audit_handler.setLevel(logging.INFO)
        audit_handler.setFormatter(JSONFormatter())
        audit_logger.addHandler(audit_handler)

        # Also log audit to console if verbose
        if verbose:
            audit_console = logging.StreamHandler(sys.stderr)
            audit_console.setLevel(logging.INFO)
            audit_console.setFormatter(JSONFormatter())
            audit_logger.addHandler(audit_console)

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)

    return session_id


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the openlabels namespace.

    Args:
        name: Logger name, typically __name__

    Returns:
        Logger instance

    Usage:
        logger = get_logger(__name__)
        logger.info("Processing file", extra={"path": "/data/file.txt"})
    """
    # If name already starts with openlabels, use as-is
    if name.startswith("openlabels"):
        return logging.getLogger(name)
    # Otherwise, add the openlabels prefix
    return logging.getLogger(f"openlabels.{name}")
