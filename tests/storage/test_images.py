"""Tests for encrypted image storage module.

Tests ImageStore, ImageFileType, and ImageFileInfo.
"""

import hashlib
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

from scrubiq.storage.database import Database
from scrubiq.storage.images import (
    ImageStore,
    ImageFileType,
    ImageFileInfo,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def mock_keys():
    """Create a mock KeyManager."""
    keys = MagicMock()
    # Simple encrypt/decrypt that just wraps in marker bytes
    keys.encrypt.side_effect = lambda data: b"ENC:" + data + b":END"
    keys.decrypt.side_effect = lambda data: data[4:-4] if data.startswith(b"ENC:") else data
    return keys


@pytest.fixture
def db_and_store(mock_keys):
    """Create a database and image store."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        images_dir = Path(tmpdir) / "images"

        db = Database(db_path)
        db.connect()

        store = ImageStore(db, mock_keys, images_dir, "session_123")

        yield db, store, images_dir

        db.close()


# =============================================================================
# IMAGE FILE TYPE ENUM TESTS
# =============================================================================

class TestImageFileType:
    """Tests for ImageFileType enum."""

    def test_face_blurred_value(self):
        """FACE_BLURRED has correct value."""
        assert ImageFileType.FACE_BLURRED.value == "face_blurred"

    def test_redacted_value(self):
        """REDACTED has correct value."""
        assert ImageFileType.REDACTED.value == "redacted"

    def test_redacted_pdf_value(self):
        """REDACTED_PDF has correct value."""
        assert ImageFileType.REDACTED_PDF.value == "redacted_pdf"

    def test_is_string_enum(self):
        """ImageFileType is a string enum."""
        assert isinstance(ImageFileType.FACE_BLURRED, str)


# =============================================================================
# IMAGE FILE INFO TESTS
# =============================================================================

class TestImageFileInfo:
    """Tests for ImageFileInfo dataclass."""

    def test_create_info(self):
        """Can create ImageFileInfo."""
        info = ImageFileInfo(
            job_id="job-123",
            file_type=ImageFileType.REDACTED,
            encrypted_path="images/job-123_redacted.enc",
            original_filename="photo.png",
            content_type="image/png",
            sha256_hash="abc123",
            size_bytes=1024,
            created_at=datetime.now(timezone.utc),
        )

        assert info.job_id == "job-123"
        assert info.file_type == ImageFileType.REDACTED
        assert info.size_bytes == 1024


# =============================================================================
# IMAGE STORE BASIC TESTS
# =============================================================================

class TestImageStoreBasic:
    """Basic tests for ImageStore."""

    def test_creates_images_dir(self, db_and_store):
        """ImageStore creates images directory."""
        db, store, images_dir = db_and_store

        assert images_dir.exists()

    def test_store_creates_file(self, db_and_store):
        """store() creates encrypted file."""
        db, store, images_dir = db_and_store

        image_data = b"fake image data"
        info = store.store(
            job_id="job-1",
            file_type=ImageFileType.REDACTED,
            image_bytes=image_data,
            original_filename="test.png",
            content_type="image/png",
        )

        # File should exist
        file_path = images_dir / "job-1_redacted.enc"
        assert file_path.exists()

    def test_store_returns_info(self, db_and_store):
        """store() returns ImageFileInfo."""
        db, store, images_dir = db_and_store

        image_data = b"fake image data"
        info = store.store(
            job_id="job-1",
            file_type=ImageFileType.REDACTED,
            image_bytes=image_data,
            original_filename="test.png",
            content_type="image/png",
        )

        assert info.job_id == "job-1"
        assert info.file_type == ImageFileType.REDACTED
        assert info.original_filename == "test.png"
        assert info.content_type == "image/png"
        assert info.size_bytes == len(image_data)

    def test_store_computes_hash(self, db_and_store):
        """store() computes SHA256 hash of plaintext."""
        db, store, images_dir = db_and_store

        image_data = b"fake image data"
        expected_hash = hashlib.sha256(image_data).hexdigest()

        info = store.store(
            job_id="job-1",
            file_type=ImageFileType.REDACTED,
            image_bytes=image_data,
            original_filename="test.png",
            content_type="image/png",
        )

        assert info.sha256_hash == expected_hash


# =============================================================================
# IMAGE STORE RETRIEVE TESTS
# =============================================================================

class TestImageStoreRetrieve:
    """Tests for ImageStore.retrieve method."""

    def test_retrieve_returns_decrypted_data(self, db_and_store):
        """retrieve() returns decrypted image data."""
        db, store, images_dir = db_and_store

        image_data = b"fake image data for retrieval"
        store.store(
            job_id="job-1",
            file_type=ImageFileType.REDACTED,
            image_bytes=image_data,
            original_filename="test.png",
            content_type="image/png",
        )

        result = store.retrieve("job-1", ImageFileType.REDACTED)

        assert result is not None
        decrypted, info = result
        assert decrypted == image_data

    def test_retrieve_returns_info(self, db_and_store):
        """retrieve() returns ImageFileInfo."""
        db, store, images_dir = db_and_store

        image_data = b"test data"
        store.store(
            job_id="job-1",
            file_type=ImageFileType.REDACTED,
            image_bytes=image_data,
            original_filename="photo.png",
            content_type="image/png",
        )

        result = store.retrieve("job-1", ImageFileType.REDACTED)

        assert result is not None
        decrypted, info = result
        assert info.original_filename == "photo.png"
        assert info.content_type == "image/png"

    def test_retrieve_nonexistent_returns_none(self, db_and_store):
        """retrieve() returns None for nonexistent job."""
        db, store, images_dir = db_and_store

        result = store.retrieve("nonexistent", ImageFileType.REDACTED)

        assert result is None

    def test_retrieve_verifies_integrity(self, db_and_store):
        """retrieve() verifies data integrity."""
        db, store, images_dir = db_and_store

        image_data = b"original data"
        store.store(
            job_id="job-1",
            file_type=ImageFileType.REDACTED,
            image_bytes=image_data,
            original_filename="test.png",
            content_type="image/png",
        )

        # Tamper with the file
        file_path = images_dir / "job-1_redacted.enc"
        file_path.write_bytes(b"ENC:corrupted data:END")

        result = store.retrieve("job-1", ImageFileType.REDACTED)

        # Should return None due to integrity failure
        assert result is None

    def test_retrieve_session_isolation(self, mock_keys):
        """retrieve() enforces session isolation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            images_dir = Path(tmpdir) / "images"

            db = Database(db_path)
            db.connect()

            store1 = ImageStore(db, mock_keys, images_dir, "session_1")
            store2 = ImageStore(db, mock_keys, images_dir, "session_2")

            # Store with session_1
            store1.store(
                job_id="job-1",
                file_type=ImageFileType.REDACTED,
                image_bytes=b"data",
                original_filename="test.png",
                content_type="image/png",
            )

            # Session 2 should not be able to retrieve
            result = store2.retrieve("job-1", ImageFileType.REDACTED)
            assert result is None

            db.close()


# =============================================================================
# IMAGE STORE GET INFO TESTS
# =============================================================================

class TestImageStoreGetInfo:
    """Tests for ImageStore.get_info method."""

    def test_get_info_returns_metadata(self, db_and_store):
        """get_info() returns metadata without decrypting."""
        db, store, images_dir = db_and_store

        store.store(
            job_id="job-1",
            file_type=ImageFileType.REDACTED,
            image_bytes=b"data",
            original_filename="test.png",
            content_type="image/png",
        )

        info = store.get_info("job-1", ImageFileType.REDACTED)

        assert info is not None
        assert info.job_id == "job-1"
        assert info.original_filename == "test.png"

    def test_get_info_nonexistent_returns_none(self, db_and_store):
        """get_info() returns None for nonexistent job."""
        db, store, images_dir = db_and_store

        info = store.get_info("nonexistent", ImageFileType.REDACTED)

        assert info is None


# =============================================================================
# IMAGE STORE HAS REDACTED IMAGE TESTS
# =============================================================================

class TestHasRedactedImage:
    """Tests for ImageStore.has_redacted_image method."""

    def test_has_redacted_image_false(self, db_and_store):
        """has_redacted_image() returns False for no image."""
        db, store, images_dir = db_and_store

        assert store.has_redacted_image("nonexistent") is False

    def test_has_redacted_image_true(self, db_and_store):
        """has_redacted_image() returns True for REDACTED type."""
        db, store, images_dir = db_and_store

        store.store(
            job_id="job-1",
            file_type=ImageFileType.REDACTED,
            image_bytes=b"data",
            original_filename="test.png",
            content_type="image/png",
        )

        assert store.has_redacted_image("job-1") is True

    def test_has_redacted_image_pdf(self, db_and_store):
        """has_redacted_image() returns True for REDACTED_PDF type."""
        db, store, images_dir = db_and_store

        store.store(
            job_id="job-1",
            file_type=ImageFileType.REDACTED_PDF,
            image_bytes=b"pdf data",
            original_filename="doc.pdf",
            content_type="application/pdf",
        )

        assert store.has_redacted_image("job-1") is True

    def test_has_redacted_image_face_blurred_only(self, db_and_store):
        """has_redacted_image() returns False for only FACE_BLURRED."""
        db, store, images_dir = db_and_store

        store.store(
            job_id="job-1",
            file_type=ImageFileType.FACE_BLURRED,
            image_bytes=b"data",
            original_filename="test.png",
            content_type="image/png",
        )

        assert store.has_redacted_image("job-1") is False


# =============================================================================
# IMAGE STORE LIST FOR JOB TESTS
# =============================================================================

class TestListForJob:
    """Tests for ImageStore.list_for_job method."""

    def test_list_for_job_empty(self, db_and_store):
        """list_for_job() returns empty for no files."""
        db, store, images_dir = db_and_store

        files = store.list_for_job("nonexistent")

        assert files == []

    def test_list_for_job_returns_all(self, db_and_store):
        """list_for_job() returns all files for job."""
        db, store, images_dir = db_and_store

        store.store("job-1", ImageFileType.FACE_BLURRED, b"d1", "f1.png", "image/png")
        store.store("job-1", ImageFileType.REDACTED, b"d2", "f1.png", "image/png")

        files = store.list_for_job("job-1")

        assert len(files) == 2


# =============================================================================
# IMAGE STORE DELETE TESTS
# =============================================================================

class TestImageStoreDelete:
    """Tests for ImageStore.delete method."""

    def test_delete_specific_type(self, db_and_store):
        """delete() removes specific file type."""
        db, store, images_dir = db_and_store

        store.store("job-1", ImageFileType.FACE_BLURRED, b"d1", "f.png", "image/png")
        store.store("job-1", ImageFileType.REDACTED, b"d2", "f.png", "image/png")

        deleted = store.delete("job-1", ImageFileType.FACE_BLURRED)

        assert deleted == 1
        assert len(store.list_for_job("job-1")) == 1

    def test_delete_all_types(self, db_and_store):
        """delete() removes all file types when type is None."""
        db, store, images_dir = db_and_store

        store.store("job-1", ImageFileType.FACE_BLURRED, b"d1", "f.png", "image/png")
        store.store("job-1", ImageFileType.REDACTED, b"d2", "f.png", "image/png")

        deleted = store.delete("job-1")

        assert deleted == 2
        assert len(store.list_for_job("job-1")) == 0

    def test_delete_removes_file_from_disk(self, db_and_store):
        """delete() removes file from disk."""
        db, store, images_dir = db_and_store

        store.store("job-1", ImageFileType.REDACTED, b"data", "f.png", "image/png")

        file_path = images_dir / "job-1_redacted.enc"
        assert file_path.exists()

        store.delete("job-1", ImageFileType.REDACTED)

        assert not file_path.exists()


# =============================================================================
# IMAGE STORE CLEANUP TESTS
# =============================================================================

class TestImageStoreCleanup:
    """Tests for ImageStore.cleanup_orphaned_files method."""

    def test_cleanup_removes_orphaned_files(self, db_and_store):
        """cleanup_orphaned_files() removes untracked files."""
        db, store, images_dir = db_and_store

        # Create an orphaned file
        orphan_path = images_dir / "orphan_file.enc"
        orphan_path.write_bytes(b"orphan data")

        removed = store.cleanup_orphaned_files()

        assert removed == 1
        assert not orphan_path.exists()

    def test_cleanup_preserves_tracked_files(self, db_and_store):
        """cleanup_orphaned_files() preserves tracked files."""
        db, store, images_dir = db_and_store

        store.store("job-1", ImageFileType.REDACTED, b"data", "f.png", "image/png")

        removed = store.cleanup_orphaned_files()

        assert removed == 0

        file_path = images_dir / "job-1_redacted.enc"
        assert file_path.exists()


# =============================================================================
# IMAGE STORE STATISTICS TESTS
# =============================================================================

class TestImageStoreStatistics:
    """Tests for ImageStore.get_storage_stats method."""

    def test_stats_empty(self, db_and_store):
        """get_storage_stats() returns zeros for empty store."""
        db, store, images_dir = db_and_store

        stats = store.get_storage_stats()

        assert stats["file_count"] == 0
        assert stats["job_count"] == 0
        assert stats["total_plaintext_bytes"] == 0

    def test_stats_with_files(self, db_and_store):
        """get_storage_stats() returns correct statistics."""
        db, store, images_dir = db_and_store

        store.store("job-1", ImageFileType.REDACTED, b"12345", "f.png", "image/png")
        store.store("job-1", ImageFileType.FACE_BLURRED, b"123", "f.png", "image/png")
        store.store("job-2", ImageFileType.REDACTED, b"1234567890", "g.png", "image/png")

        stats = store.get_storage_stats()

        assert stats["file_count"] == 3
        assert stats["job_count"] == 2
        assert stats["total_plaintext_bytes"] == 5 + 3 + 10
        assert stats["total_encrypted_bytes"] > 0
        assert str(images_dir) in stats["images_dir"]


# =============================================================================
# IMAGE STORE FILE NAMING TESTS
# =============================================================================

class TestImageStoreFileNaming:
    """Tests for file naming conventions."""

    def test_redacted_filename(self, db_and_store):
        """REDACTED files use correct naming."""
        db, store, images_dir = db_and_store

        info = store.store("job-123", ImageFileType.REDACTED, b"d", "f.png", "image/png")

        assert info.encrypted_path == "images/job-123_redacted.enc"

    def test_face_blurred_filename(self, db_and_store):
        """FACE_BLURRED files use correct naming."""
        db, store, images_dir = db_and_store

        info = store.store("job-123", ImageFileType.FACE_BLURRED, b"d", "f.png", "image/png")

        assert info.encrypted_path == "images/job-123_face_blurred.enc"

    def test_redacted_pdf_filename(self, db_and_store):
        """REDACTED_PDF files use correct naming."""
        db, store, images_dir = db_and_store

        info = store.store("job-123", ImageFileType.REDACTED_PDF, b"d", "f.pdf", "application/pdf")

        assert info.encrypted_path == "images/job-123_redacted_pdf.pdf.enc"


# =============================================================================
# IMAGE STORE UPSERT TESTS
# =============================================================================

class TestImageStoreUpsert:
    """Tests for store() upsert behavior."""

    def test_store_replaces_existing(self, db_and_store):
        """store() replaces existing file for same job+type."""
        db, store, images_dir = db_and_store

        store.store("job-1", ImageFileType.REDACTED, b"original", "f.png", "image/png")
        store.store("job-1", ImageFileType.REDACTED, b"updated", "f.png", "image/png")

        result = store.retrieve("job-1", ImageFileType.REDACTED)
        decrypted, info = result

        assert decrypted == b"updated"
        assert len(store.list_for_job("job-1")) == 1
