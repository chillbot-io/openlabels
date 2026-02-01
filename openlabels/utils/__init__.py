"""OpenLabels utility modules."""

from .validation import (
    validate_path_for_subprocess,
    validate_xattr_value,
    SHELL_METACHARACTERS,
)
from .hashing import quick_hash
from .retry import (
    with_retry,
    with_resilience,
    CircuitBreaker,
    CircuitBreakerOpenError,
    get_cloud_transient_exceptions,
    TRANSIENT_EXCEPTIONS,
)

__all__ = [
    "validate_path_for_subprocess",
    "validate_xattr_value",
    "SHELL_METACHARACTERS",
    "quick_hash",
    # Retry utilities (GA-FIX 1.4)
    "with_retry",
    "with_resilience",
    "CircuitBreaker",
    "CircuitBreakerOpenError",
    "get_cloud_transient_exceptions",
    "TRANSIENT_EXCEPTIONS",
]
