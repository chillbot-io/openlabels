"""Key derivation using Scrypt (preferred) or PBKDF2 (fallback)."""

import hashlib
import logging
import secrets
from typing import Tuple

logger = logging.getLogger(__name__)

SALT_SIZE = 16
KEY_SIZE = 32  # 256 bits

# PBKDF2 iterations per OWASP 2023: 600,000 for SHA-256
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
PBKDF2_ITERATIONS = 600_000

# Scrypt limits for interactive use
# n=2^14 (~0.5s), n=2^15 (~1s), n=2^16 (~3s), n=2^17 (~10s+)
SCRYPT_N_MIN = 2 ** 14  # 16384 - minimum per cryptography library
SCRYPT_N_MAX = 2 ** 15  # 32768 - cap for interactive unlock (~1s)

# Legacy vaults created before the fix used this value (very slow: ~30s)
SCRYPT_N_LEGACY = 2 ** 17  # 131072 - DO NOT USE for new vaults


def derive_key(
    key_material: str,
    salt: bytes = None,
    memory_mb: int = 16,  # Lower default for fast unlock
    scrypt_n: int = None,  # Override n directly (for loading existing vaults)
) -> Tuple[bytes, bytes, int]:
    """
    Derive 256-bit key from key material using Scrypt (preferred) or PBKDF2 (fallback).

    Scrypt parameters target memory_mb of memory usage, capped at n=2^15
    for interactive unlock (takes ~1 second).

    If scrypt_n is provided, use that value directly (for existing vaults).

    PBKDF2 uses fixed 600K iterations per OWASP 2023 guidelines.

    Returns: (derived_key, salt, scrypt_n)
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.backends import default_backend

        if scrypt_n is not None:
            # Use provided n (loading existing vault)
            n = scrypt_n
        else:
            # Calculate n from target memory, then clamp to safe range
            target_bytes = memory_mb * 1024 * 1024
            n_target = target_bytes // 1024
            
            # Round to nearest power of 2 (not up)
            if n_target > 0:
                n = 1 << (n_target.bit_length() - 1)
                if n_target - n > n // 2:
                    n = n << 1
            else:
                n = SCRYPT_N_MIN
            
            # Clamp to safe range for interactive use
            n = max(SCRYPT_N_MIN, min(SCRYPT_N_MAX, n))

        kdf = Scrypt(
            salt=salt,
            length=KEY_SIZE,
            n=n,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(key_material.encode("utf-8"))
        return key, salt, n

    except ImportError:
        # PBKDF2 fallback - less memory-hard but functional
        logger.warning(
            "cryptography library not installed - using PBKDF2 fallback. "
            "Scrypt provides better protection against GPU attacks. "
            "Install with: pip install cryptography"
        )
        
        key = hashlib.pbkdf2_hmac(
            "sha256",
            key_material.encode("utf-8"),
            salt,
            iterations=PBKDF2_ITERATIONS,
            dklen=KEY_SIZE
        )
        return key, salt, 0  # 0 indicates PBKDF2 was used
