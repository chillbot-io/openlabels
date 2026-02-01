"""
OpenLabels Authentication & Authorization.

Provides user management, JWT sessions, encrypted vaults, and admin recovery.

Usage:
    from openlabels.auth import AuthManager

    auth = AuthManager()

    # First-time setup (creates admin)
    if auth.needs_setup():
        recovery_keys = auth.setup_admin("admin", "password123", email="admin@example.com")
        # Save recovery_keys securely!

    # Login
    session = auth.login("admin", "password123")

    # Access vault
    vault = session.get_vault()
    vault.store_scan_result(file_path, spans, source="openlabels")

    # Logout
    auth.logout(session.token)
"""

from .models import User, Session, UserRole
from .users import UserManager
from .jwt import JWTManager
from .recovery import RecoveryManager
from .crypto import CryptoProvider

__all__ = [
    "AuthManager",
    "AuthenticationError",
    "User",
    "Session",
    "UserRole",
    "UserManager",
    "JWTManager",
    "RecoveryManager",
    "CryptoProvider",
]


class AuthManager:
    """
    Main entry point for authentication operations.

    Coordinates user management, JWT tokens, and recovery keys.
    Thread-safe for use from Qt GUI.
    """

    def __init__(self, data_dir: str | None = None):
        """
        Initialize auth manager.

        Args:
            data_dir: Base directory for auth data. Defaults to ~/.openlabels/
        """
        from pathlib import Path

        self._data_dir = Path(data_dir) if data_dir else Path.home() / ".openlabels"
        self._crypto = CryptoProvider()
        self._users = UserManager(self._data_dir / "users", self._crypto)
        self._jwt = JWTManager(self._data_dir / "jwt_secret")
        self._recovery = RecoveryManager(self._data_dir / "recovery", self._crypto)
        self._active_sessions: dict[str, Session] = {}

    def needs_setup(self) -> bool:
        """Check if first-time setup is needed (no admin exists)."""
        return not self._users.admin_exists()

    def setup_admin(
        self,
        username: str,
        password: str,
        email: str | None = None,
        subscribe_updates: bool = True,
    ) -> list[str]:
        """
        First-time setup: create admin user.

        Args:
            username: Admin username
            password: Admin password
            email: Optional email for updates
            subscribe_updates: Whether to subscribe to OpenLabels updates

        Returns:
            List of recovery keys (save these securely!)

        Raises:
            RuntimeError: If admin already exists
        """
        if self._users.admin_exists():
            raise RuntimeError("Admin user already exists")

        # Create admin user
        user, dek = self._users.create_user(
            username=username,
            password=password,
            role=UserRole.ADMIN,
            email=email,
            subscribe_updates=subscribe_updates,
        )

        # Generate recovery keys
        recovery_keys = self._recovery.generate_keys(user, dek)

        # Setup audit log encryption with admin's DEK
        from openlabels.vault.audit import AuditLog
        audit = AuditLog(self._data_dir, self._crypto)
        audit.setup_admin_key(dek)

        return recovery_keys

    def create_user(
        self,
        admin_session: Session,
        username: str,
        password: str,
        role: UserRole = UserRole.USER,
    ) -> User:
        """
        Create a new user (admin only).

        Args:
            admin_session: Authenticated admin session
            username: New user's username
            password: New user's password
            role: User role (default: USER)

        Returns:
            Created User object

        Raises:
            PermissionError: If session is not admin
            ValueError: If username already exists
        """
        if not admin_session.is_admin():
            raise PermissionError("Only admin can create users")

        user, _dek = self._users.create_user(
            username=username,
            password=password,
            role=role,
        )

        return user

    def login(self, username: str, password: str) -> Session:
        """
        Authenticate user and create session.

        Args:
            username: Username
            password: Password

        Returns:
            Authenticated Session with JWT token

        Raises:
            AuthenticationError: If credentials invalid
        """
        result = self._users.authenticate(username, password)
        if result is None:
            raise AuthenticationError("Invalid username or password")

        user, dek = result

        # Create JWT token
        token = self._jwt.create_token(
            user_id=user.id,
            username=user.username,
            role=user.role.value,
        )

        # Create session
        session = Session(
            token=token,
            user=user,
            _dek=dek,
        )

        # Track active session
        self._active_sessions[token] = session

        # If admin, flush any queued audit entries
        if user.is_admin():
            from openlabels.vault.audit import AuditLog
            audit = AuditLog(self._data_dir, self._crypto)
            try:
                audit.flush_queue(dek)
            except Exception:
                pass  # Ignore flush errors

        return session

    def logout(self, token: str) -> None:
        """
        End a session.

        Args:
            token: JWT token to invalidate
        """
        if token in self._active_sessions:
            del self._active_sessions[token]

    def verify_session(self, token: str) -> Session | None:
        """
        Verify a JWT token and return session if valid.

        Args:
            token: JWT token

        Returns:
            Session if valid, None otherwise
        """
        # Check active sessions first
        if token in self._active_sessions:
            return self._active_sessions[token]

        # Verify JWT
        payload = self._jwt.verify_token(token)
        if payload is None:
            return None

        # Get user
        user = self._users.get_user_by_id(payload["sub"])
        if user is None:
            return None

        # Note: We can't recover DEK without password, so this session
        # won't have vault access. For full vault access, user must login again.
        return Session(
            token=token,
            user=user,
            _dek=None,  # No DEK - vault access limited
        )

    def reset_user_vault(self, admin_session: Session, username: str) -> None:
        """
        Reset a user's vault (admin only). User loses vault data.

        Args:
            admin_session: Authenticated admin session
            username: User whose vault to reset

        Raises:
            PermissionError: If session is not admin
        """
        if not admin_session.is_admin():
            raise PermissionError("Only admin can reset user vaults")

        user = self._users.get_user(username)
        if user is None:
            raise ValueError(f"User not found: {username}")

        # Clear the user's vault
        from openlabels.vault import Vault
        # We need a dummy DEK just to get the vault path
        # The clear() method just deletes files, doesn't need real DEK
        vault = Vault(user_id=user.id, dek=b"\x00" * 32, data_dir=self._data_dir)
        vault.clear()

    def recover_with_key(self, recovery_key: str, new_password: str) -> bool:
        """
        Recover admin account using recovery key.

        Args:
            recovery_key: One of the admin recovery keys
            new_password: New password to set

        Returns:
            True if recovery successful
        """
        # Find admin user
        admin_user = None
        for user in self._users.list_users():
            if user.is_admin():
                admin_user = user
                break

        if admin_user is None:
            return False

        # Attempt recovery
        return self._recovery.recover_admin(
            user_id=admin_user.id,
            recovery_key=recovery_key,
            new_password=new_password,
            users_manager=self._users,
        )

    def list_users(self) -> list[User]:
        """List all users."""
        return list(self._users.list_users())

    def get_current_user(self, token: str) -> User | None:
        """Get the user for a token."""
        session = self.verify_session(token)
        return session.user if session else None


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass
