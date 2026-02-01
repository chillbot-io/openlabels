"""
User management for OpenLabels.

Handles user CRUD operations, credential storage, and authentication.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .models import User, UserRole, AuthCredentials
from .crypto import CryptoProvider


class UserManager:
    """
    Manages user accounts and credentials.

    Users are stored as JSON files in the users directory:
        users/
        ├── index.json           # Username -> user_id mapping
        ├── {user_id}/
        │   ├── profile.json     # User metadata
        │   └── credentials.json # Password hash, salt, encrypted DEK

    Example:
        users = UserManager(Path("~/.openlabels/users"), crypto)

        # Create admin
        user, dek = users.create_user("admin", "password", UserRole.ADMIN)

        # Authenticate
        user, dek = users.authenticate("admin", "password")

        # List users
        for user in users.list_users():
            print(user.username)
    """

    def __init__(self, users_dir: Path, crypto: CryptoProvider):
        """
        Initialize user manager.

        Args:
            users_dir: Directory for user data
            crypto: Crypto provider for hashing/encryption
        """
        self._users_dir = Path(users_dir)
        self._crypto = crypto
        self._index_path = self._users_dir / "index.json"

    def _ensure_dirs(self) -> None:
        """Ensure user directories exist."""
        self._users_dir.mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> dict[str, str]:
        """Load username -> user_id index."""
        if self._index_path.exists():
            return json.loads(self._index_path.read_text())
        return {}

    def _save_index(self, index: dict[str, str]) -> None:
        """Save username -> user_id index."""
        self._ensure_dirs()
        self._index_path.write_text(json.dumps(index, indent=2))

    def _user_dir(self, user_id: str) -> Path:
        """Get directory for a specific user."""
        return self._users_dir / user_id

    def _profile_path(self, user_id: str) -> Path:
        """Get profile path for a user."""
        return self._user_dir(user_id) / "profile.json"

    def _credentials_path(self, user_id: str) -> Path:
        """Get credentials path for a user."""
        return self._user_dir(user_id) / "credentials.json"

    def admin_exists(self) -> bool:
        """Check if an admin user exists."""
        for user in self.list_users():
            if user.role == UserRole.ADMIN:
                return True
        return False

    def user_exists(self, username: str) -> bool:
        """Check if a username is taken."""
        index = self._load_index()
        return username.lower() in {k.lower() for k in index.keys()}

    def get_user(self, username: str) -> User | None:
        """
        Get a user by username.

        Args:
            username: The username to look up

        Returns:
            User if found, None otherwise
        """
        index = self._load_index()

        # Case-insensitive lookup
        user_id = None
        for uname, uid in index.items():
            if uname.lower() == username.lower():
                user_id = uid
                break

        if user_id is None:
            return None

        profile_path = self._profile_path(user_id)
        if not profile_path.exists():
            return None

        data = json.loads(profile_path.read_text())
        return User.from_dict(data)

    def get_user_by_id(self, user_id: str) -> User | None:
        """
        Get a user by ID.

        Args:
            user_id: The user's unique ID

        Returns:
            User if found, None otherwise
        """
        profile_path = self._profile_path(user_id)
        if not profile_path.exists():
            return None

        data = json.loads(profile_path.read_text())
        return User.from_dict(data)

    def list_users(self) -> Iterator[User]:
        """
        Iterate over all users.

        Yields:
            User objects
        """
        index = self._load_index()
        for username, user_id in index.items():
            user = self.get_user_by_id(user_id)
            if user:
                yield user

    def create_user(
        self,
        username: str,
        password: str,
        role: UserRole = UserRole.USER,
        email: str | None = None,
        subscribe_updates: bool = False,
    ) -> tuple[User, bytes]:
        """
        Create a new user.

        Args:
            username: Unique username
            password: User's password
            role: User role (default: USER)
            email: Optional email address
            subscribe_updates: Whether to subscribe to updates

        Returns:
            Tuple of (User, DEK) where DEK is the data encryption key

        Raises:
            ValueError: If username already exists
        """
        if self.user_exists(username):
            raise ValueError(f"Username already exists: {username}")

        # Generate user ID and keys
        user_id = str(uuid.uuid4())
        salt = self._crypto.generate_salt()
        dek = self._crypto.generate_key()

        # Hash password
        password_hash = self._crypto.hash_password(password, salt)

        # Derive KEK from password and encrypt DEK
        kek = self._crypto.derive_key(password, salt)
        encrypted_dek = self._crypto.encrypt(dek, kek)

        # Create user object
        user = User(
            id=user_id,
            username=username,
            role=role,
            email=email,
            subscribe_updates=subscribe_updates,
        )

        # Create credentials
        credentials = AuthCredentials(
            user_id=user_id,
            password_hash=password_hash,
            salt=salt,
            dek_encrypted=encrypted_dek.ciphertext,
            dek_nonce=encrypted_dek.nonce,
        )

        # Save to disk
        self._ensure_dirs()
        user_dir = self._user_dir(user_id)
        user_dir.mkdir(parents=True, exist_ok=True)

        self._profile_path(user_id).write_text(json.dumps(user.to_dict(), indent=2))
        self._credentials_path(user_id).write_text(json.dumps(credentials.to_dict(), indent=2))

        # Update index
        index = self._load_index()
        index[username] = user_id
        self._save_index(index)

        return user, dek

    def authenticate(self, username: str, password: str) -> tuple[User, bytes] | None:
        """
        Authenticate a user and return their DEK.

        Args:
            username: Username
            password: Password

        Returns:
            Tuple of (User, DEK) if valid, None if invalid
        """
        user = self.get_user(username)
        if user is None:
            return None

        credentials_path = self._credentials_path(user.id)
        if not credentials_path.exists():
            return None

        credentials = AuthCredentials.from_dict(
            json.loads(credentials_path.read_text())
        )

        # Verify password
        if not self._crypto.verify_password(password, credentials.password_hash, credentials.salt):
            return None

        # Derive KEK and decrypt DEK
        kek = self._crypto.derive_key(password, credentials.salt)
        try:
            from .crypto import EncryptedData
            encrypted_dek = EncryptedData(
                ciphertext=credentials.dek_encrypted,
                nonce=credentials.dek_nonce,
            )
            dek = self._crypto.decrypt(encrypted_dek, kek)
        except Exception:
            return None

        # Update last login
        user.last_login = datetime.now(timezone.utc)
        self._profile_path(user.id).write_text(json.dumps(user.to_dict(), indent=2))

        return user, dek

    def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
    ) -> bool:
        """
        Change a user's password.

        Args:
            user_id: User's ID
            old_password: Current password
            new_password: New password

        Returns:
            True if successful, False if old password invalid
        """
        user = self.get_user_by_id(user_id)
        if user is None:
            return False

        # Authenticate with old password to get DEK
        result = self.authenticate(user.username, old_password)
        if result is None:
            return False

        _, dek = result

        # Generate new salt and hash
        new_salt = self._crypto.generate_salt()
        new_hash = self._crypto.hash_password(new_password, new_salt)

        # Re-encrypt DEK with new password
        new_kek = self._crypto.derive_key(new_password, new_salt)
        encrypted_dek = self._crypto.encrypt(dek, new_kek)

        # Update credentials
        credentials = AuthCredentials(
            user_id=user_id,
            password_hash=new_hash,
            salt=new_salt,
            dek_encrypted=encrypted_dek.ciphertext,
            dek_nonce=encrypted_dek.nonce,
        )

        self._credentials_path(user_id).write_text(json.dumps(credentials.to_dict(), indent=2))
        return True

    def delete_user(self, user_id: str) -> bool:
        """
        Delete a user and their data.

        Args:
            user_id: User's ID

        Returns:
            True if deleted, False if not found
        """
        user = self.get_user_by_id(user_id)
        if user is None:
            return False

        # Remove from index
        index = self._load_index()
        index = {k: v for k, v in index.items() if v != user_id}
        self._save_index(index)

        # Remove user directory
        user_dir = self._user_dir(user_id)
        if user_dir.exists():
            import shutil
            shutil.rmtree(user_dir)

        return True

    def get_credentials(self, user_id: str) -> AuthCredentials | None:
        """
        Get a user's credentials (for recovery operations).

        Args:
            user_id: User's ID

        Returns:
            AuthCredentials if found, None otherwise
        """
        cred_path = self._credentials_path(user_id)
        if not cred_path.exists():
            return None

        return AuthCredentials.from_dict(json.loads(cred_path.read_text()))

    def update_credentials(self, user_id: str, credentials: AuthCredentials) -> None:
        """
        Update a user's credentials.

        Args:
            user_id: User's ID
            credentials: New credentials
        """
        self._credentials_path(user_id).write_text(
            json.dumps(credentials.to_dict(), indent=2)
        )
