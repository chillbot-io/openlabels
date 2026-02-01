"""
Authentication data models.

Defines User, Session, and related dataclasses.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


def _utc_now() -> datetime:
    """Get current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openlabels.vault import Vault


class UserRole(Enum):
    """User permission levels."""
    ADMIN = "admin"      # Can manage users, view audit logs, recover accounts
    USER = "user"        # Standard user with own vault


@dataclass
class User:
    """
    User account information.

    Note: Password hash and salt are stored separately in secure storage,
    not in this object.
    """
    id: str                          # UUID
    username: str                    # Unique username
    role: UserRole                   # Permission level
    email: str | None = None         # Optional email for updates
    created_at: datetime = field(default_factory=_utc_now)
    last_login: datetime | None = None
    subscribe_updates: bool = False  # Opted into email updates

    def is_admin(self) -> bool:
        """Check if user has admin privileges."""
        return self.role == UserRole.ADMIN

    def to_dict(self) -> dict:
        """Serialize to dictionary (for storage)."""
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role.value,
            "email": self.email,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "subscribe_updates": self.subscribe_updates,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        """Deserialize from dictionary."""
        return cls(
            id=data["id"],
            username=data["username"],
            role=UserRole(data["role"]),
            email=data.get("email"),
            created_at=datetime.fromisoformat(data["created_at"]),
            last_login=datetime.fromisoformat(data["last_login"]) if data.get("last_login") else None,
            subscribe_updates=data.get("subscribe_updates", False),
        )


@dataclass
class Session:
    """
    Authenticated user session.

    Contains the JWT token and provides access to user's vault.
    """
    token: str                       # JWT token
    user: User                       # Authenticated user
    created_at: datetime = field(default_factory=_utc_now)

    # Internal: decrypted data encryption key (held in memory only)
    _dek: bytes | None = field(default=None, repr=False)

    def get_vault(self) -> "Vault":
        """
        Get the user's vault for storing/retrieving sensitive data.

        Returns:
            Vault instance decrypted with session key

        Raises:
            RuntimeError: If session has no DEK (shouldn't happen)
        """
        if self._dek is None:
            raise RuntimeError("Session has no decryption key")

        from openlabels.vault import Vault
        return Vault(user_id=self.user.id, dek=self._dek)

    def is_admin(self) -> bool:
        """Check if session has admin privileges."""
        return self.user.is_admin()


@dataclass
class AuthCredentials:
    """
    Stored credentials for a user (never exposed directly).
    """
    user_id: str
    password_hash: bytes             # Argon2 hash
    salt: bytes                      # Unique salt for this user
    dek_encrypted: bytes             # DEK wrapped with password-derived KEK
    dek_nonce: bytes                 # Nonce for DEK encryption

    def to_dict(self) -> dict:
        """Serialize to dictionary (for storage)."""
        import base64
        return {
            "user_id": self.user_id,
            "password_hash": base64.b64encode(self.password_hash).decode(),
            "salt": base64.b64encode(self.salt).decode(),
            "dek_encrypted": base64.b64encode(self.dek_encrypted).decode(),
            "dek_nonce": base64.b64encode(self.dek_nonce).decode(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuthCredentials":
        """Deserialize from dictionary."""
        import base64
        return cls(
            user_id=data["user_id"],
            password_hash=base64.b64decode(data["password_hash"]),
            salt=base64.b64decode(data["salt"]),
            dek_encrypted=base64.b64decode(data["dek_encrypted"]),
            dek_nonce=base64.b64decode(data["dek_nonce"]),
        )


@dataclass
class RecoveryKey:
    """
    Admin recovery key data.

    Multiple recovery keys are generated; each can recover the admin account.
    """
    key_id: str                      # Short identifier (first 8 chars of hash)
    key_hash: bytes                  # Hash of the full recovery key
    dek_encrypted: bytes             # DEK wrapped with this recovery key
    dek_nonce: bytes                 # Nonce for DEK encryption
    created_at: datetime = field(default_factory=_utc_now)
    used: bool = False               # True if this key has been used for recovery

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        import base64
        return {
            "key_id": self.key_id,
            "key_hash": base64.b64encode(self.key_hash).decode(),
            "dek_encrypted": base64.b64encode(self.dek_encrypted).decode(),
            "dek_nonce": base64.b64encode(self.dek_nonce).decode(),
            "created_at": self.created_at.isoformat(),
            "used": self.used,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RecoveryKey":
        """Deserialize from dictionary."""
        import base64
        return cls(
            key_id=data["key_id"],
            key_hash=base64.b64decode(data["key_hash"]),
            dek_encrypted=base64.b64decode(data["dek_encrypted"]),
            dek_nonce=base64.b64decode(data["dek_nonce"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            used=data.get("used", False),
        )
