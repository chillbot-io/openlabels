"""
PHI-Safe Logging Utilities

Provides logging wrappers that automatically redact potential PHI before logging.
NEVER log raw user input or restored text - use these utilities instead.

Usage:
    from .logging_utils import get_phi_safe_logger

    logger = get_phi_safe_logger(__name__)
    logger.info("Processing message", text=user_input)  # Auto-redacted
    logger.debug_safe("Chat flow", tokens=["[NAME_1]"], count=5)  # Safe data only
"""

import logging
import os
import re
from typing import Any


# --- PRODUCTION MODE DETECTION ---
def _is_production_mode() -> bool:
    """Check if running in production mode."""
    # Check SCRUBIQ_ENV
    cr_env = os.environ.get("SCRUBIQ_ENV", "").lower()
    if cr_env == "production":
        return True
    
    # Check PROD flag
    prod_flag = os.environ.get("PROD", "").lower()
    if prod_flag in ("1", "true", "yes"):
        return True
    
    # Check NODE_ENV (common in containerized deployments)
    node_env = os.environ.get("NODE_ENV", "").lower()
    if node_env == "production":
        return True
    
    return False


_PRODUCTION_MODE = _is_production_mode()


# --- PHI PATTERNS FOR LOG SANITIZATION ---
# Patterns that indicate potential PHI - used for log sanitization
_PHI_PATTERNS = [
    # SSN patterns
    (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN-REDACTED]'),
    (r'\b\d{3}\s\d{2}\s\d{4}\b', '[SSN-REDACTED]'),
    (r'\b\d{9}\b', '[9DIGIT-REDACTED]'),
    
    # Phone patterns
    (r'\(\d{3}\)\s*\d{3}-\d{4}', '[PHONE-REDACTED]'),
    (r'\b\d{3}-\d{3}-\d{4}\b', '[PHONE-REDACTED]'),
    (r'\b\d{3}\.\d{3}\.\d{4}\b', '[PHONE-REDACTED]'),
    
    # Email
    (r'\b[\w.-]+@[\w.-]+\.\w+\b', '[EMAIL-REDACTED]'),
    
    # Dates that might be DOB
    (r'\b\d{1,2}/\d{1,2}/\d{2,4}\b', '[DATE-REDACTED]'),
    (r'\b\d{4}-\d{2}-\d{2}\b', '[DATE-REDACTED]'),
    
    # Credit card (16 digits with optional separators)
    (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CC-REDACTED]'),
    
    # MRN-like patterns (6-10 digits often with prefix)
    (r'\b[A-Z]{0,3}\d{6,10}\b', '[ID-REDACTED]'),
]

# Compile patterns for efficiency
_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), r) for p, r in _PHI_PATTERNS]


def sanitize_for_logging(text: str, max_length: int = 200) -> str:
    """
    Sanitize text for safe logging by redacting potential PHI patterns.
    
    Args:
        text: Input text that may contain PHI
        max_length: Truncate to this length (0 for no truncation)
        
    Returns:
        Sanitized string safe for logging
    """
    if not text:
        return ""
    
    result = text
    
    # Apply all redaction patterns
    for pattern, replacement in _COMPILED_PATTERNS:
        result = pattern.sub(replacement, result)
    
    # Truncate if needed
    if max_length > 0 and len(result) > max_length:
        result = result[:max_length] + "...[truncated]"
    
    return result


def safe_repr(obj: Any, max_length: int = 100) -> str:
    """
    Create a safe string representation of an object for logging.
    
    - Strings are sanitized for PHI
    - Lists/dicts show length only
    - Other types show type name
    """
    if obj is None:
        return "None"
    elif isinstance(obj, str):
        return f'"{sanitize_for_logging(obj, max_length)}"'
    elif isinstance(obj, (list, tuple)):
        return f"[{type(obj).__name__} len={len(obj)}]"
    elif isinstance(obj, dict):
        return f"{{dict keys={list(obj.keys())}}}"
    elif isinstance(obj, (int, float, bool)):
        return str(obj)
    else:
        return f"<{type(obj).__name__}>"


class PHISafeLogger:
    """
    Logger wrapper that provides PHI-safe logging methods.
    
    Usage:
        logger = PHISafeLogger(__name__)
        
        # For potentially unsafe data - auto-sanitized
        logger.info("Processing", text=user_input, patient_name=name)
        
        # For known-safe data (tokens, counts, timing)
        logger.debug_safe("Stats", tokens=["[NAME_1]"], time_ms=150)
    """
    
    def __init__(self, name: str):
        self._logger = logging.getLogger(name)
    
    def _format_safe_message(self, message: str, **kwargs) -> str:
        """Format message with sanitized kwargs."""
        # SECURITY: Always sanitize the message itself
        sanitized_message = sanitize_for_logging(message, max_length=0)
        
        if not kwargs:
            return sanitized_message
        
        parts = [sanitized_message]
        for key, value in kwargs.items():
            parts.append(f"{key}={safe_repr(value)}")
        
        return " | ".join(parts)
    
    def debug(self, message: str, **kwargs):
        """Debug log with auto-sanitization of kwargs."""
        self._logger.debug(self._format_safe_message(message, **kwargs))
    
    def info(self, message: str, **kwargs):
        """Info log with auto-sanitization of kwargs."""
        self._logger.info(self._format_safe_message(message, **kwargs))
    
    def warning(self, message: str, **kwargs):
        """Warning log with auto-sanitization of kwargs."""
        self._logger.warning(self._format_safe_message(message, **kwargs))
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        """Error log with auto-sanitization of kwargs."""
        self._logger.error(self._format_safe_message(message, **kwargs), exc_info=exc_info)
    
    def exception(self, message: str, **kwargs):
        """Exception log with auto-sanitization of kwargs. Includes traceback."""
        self._logger.exception(self._format_safe_message(message, **kwargs))
    
    def debug_safe(self, message: str, **kwargs):
        """
        Debug log for known-safe data (no sanitization).
        
        Use this for:
        - Token strings like [NAME_1]
        - Numeric counts and timing
        - Entity types
        - Processing status
        """
        parts = [message]
        for key, value in kwargs.items():
            parts.append(f"{key}={value}")
        self._logger.debug(" | ".join(parts))
    
    def info_safe(self, message: str, **kwargs):
        """Info log for known-safe data (no sanitization)."""
        parts = [message]
        for key, value in kwargs.items():
            parts.append(f"{key}={value}")
        self._logger.info(" | ".join(parts))


def get_phi_safe_logger(name: str) -> PHISafeLogger:
    """
    Get a PHI-safe logger for the given module name.
    
    Args:
        name: Usually __name__ from the calling module
        
    Returns:
        PHISafeLogger instance
    """
    return PHISafeLogger(name)


def is_production_mode() -> bool:
    """Check if running in production mode."""
    return _PRODUCTION_MODE
