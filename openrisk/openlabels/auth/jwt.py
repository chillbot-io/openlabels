"""
JWT token management for OpenLabels sessions.

Provides stateless session tokens with configurable expiry.
Designed for future client-server architecture.
"""

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# Default token expiry (can be overridden)
DEFAULT_TOKEN_EXPIRY_HOURS = 24 * 7  # 1 week


class JWTManager:
    """
    JWT token creation and verification.

    Uses PyJWT for token operations. Secret is persisted to disk
    so tokens survive app restarts.

    Example:
        jwt_mgr = JWTManager(Path("~/.openlabels/jwt_secret"))

        # Create token
        token = jwt_mgr.create_token(user_id="123", role="admin")

        # Verify token
        payload = jwt_mgr.verify_token(token)
        if payload:
            print(f"User: {payload['user_id']}")
    """

    def __init__(
        self,
        secret_path: Path,
        expiry_hours: int = DEFAULT_TOKEN_EXPIRY_HOURS,
    ):
        """
        Initialize JWT manager.

        Args:
            secret_path: Path to store/load the signing secret
            expiry_hours: Token expiry in hours
        """
        self._secret_path = Path(secret_path)
        self._expiry_hours = expiry_hours
        self._secret: bytes | None = None
        self._jwt = None

    def _get_jwt(self):
        """Lazy load PyJWT."""
        if self._jwt is None:
            try:
                import jwt
                self._jwt = jwt
            except ImportError:
                raise ImportError(
                    "PyJWT is required for authentication. "
                    "Install with: pip install openlabels[auth]"
                )
        return self._jwt

    def _get_secret(self) -> bytes:
        """Get or create the signing secret."""
        if self._secret is not None:
            return self._secret

        if self._secret_path.exists():
            self._secret = self._secret_path.read_bytes()
        else:
            # Generate new secret
            self._secret = secrets.token_bytes(32)
            self._secret_path.parent.mkdir(parents=True, exist_ok=True)
            self._secret_path.write_bytes(self._secret)
            # Secure permissions (owner read/write only)
            self._secret_path.chmod(0o600)

        return self._secret

    def create_token(
        self,
        user_id: str,
        username: str,
        role: str,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """
        Create a new JWT token.

        Args:
            user_id: User's unique ID
            username: User's username
            role: User's role (admin/user)
            extra_claims: Additional claims to include

        Returns:
            Encoded JWT token string
        """
        jwt = self._get_jwt()
        secret = self._get_secret()

        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,          # Subject (user ID)
            "username": username,
            "role": role,
            "iat": now,              # Issued at
            "exp": now + timedelta(hours=self._expiry_hours),  # Expiry
            "jti": secrets.token_hex(16),  # Unique token ID
        }

        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, secret, algorithm="HS256")

    def verify_token(self, token: str) -> dict[str, Any] | None:
        """
        Verify a JWT token and return its payload.

        Args:
            token: The JWT token string

        Returns:
            Token payload if valid, None if invalid/expired
        """
        jwt_lib = self._get_jwt()
        secret = self._get_secret()

        try:
            payload = jwt_lib.decode(token, secret, algorithms=["HS256"])
            return payload
        except jwt_lib.ExpiredSignatureError:
            return None
        except jwt_lib.InvalidTokenError:
            return None

    def refresh_token(self, token: str) -> str | None:
        """
        Refresh a valid token with a new expiry.

        Args:
            token: Current valid token

        Returns:
            New token if current is valid, None otherwise
        """
        payload = self.verify_token(token)
        if payload is None:
            return None

        return self.create_token(
            user_id=payload["sub"],
            username=payload["username"],
            role=payload["role"],
        )

    def invalidate_secret(self) -> None:
        """
        Invalidate all tokens by rotating the secret.

        Warning: This invalidates ALL active sessions.
        """
        self._secret = secrets.token_bytes(32)
        self._secret_path.write_bytes(self._secret)
        self._secret_path.chmod(0o600)
