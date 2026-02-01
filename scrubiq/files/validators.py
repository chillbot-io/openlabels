"""
File validation for uploads.

Validates file types, sizes, extensions, AND magic bytes before processing.

SECURITY FIX: Added magic byte validation to prevent attackers from
uploading malicious files by simply renaming extensions or spoofing
Content-Type headers.
"""

import logging
import os
import re
from pathlib import Path
from typing import Optional, Union

from ..constants import MAX_FILE_SIZE_BYTES, MAX_FILENAME_LENGTH

logger = logging.getLogger(__name__)


class FileValidationError(Exception):
    """Raised when file validation fails."""
    pass


def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filename to prevent injection attacks.
    
    Removes:
    - Path components (prevents directory traversal)
    - Null bytes and control characters
    - Characters dangerous for HTML/logs (<, >, quotes)
    - Shell metacharacters
    
    Args:
        filename: Original filename from upload
        
    Returns:
        Sanitized filename safe for storage and display
    """
    if not filename:
        return "unknown"
    
    # Remove path components (handles both Unix and Windows paths)
    filename = os.path.basename(filename)
    
    # Remove null bytes and control characters (0x00-0x1f)
    # Also remove: < > : " / \ | ? * (dangerous for various systems)
    filename = re.sub(r'[\x00-\x1f<>:"/\\|?*\'`$;!&()]', '_', filename)
    
    # Collapse multiple underscores/dots
    filename = re.sub(r'_+', '_', filename)
    filename = re.sub(r'\.+', '.', filename)
    
    # Remove leading/trailing underscores and dots
    filename = filename.strip('_. ')
    
    # Limit length (255 is common filesystem limit, use MAX_FILENAME_LENGTH for safety)
    if len(filename) > MAX_FILENAME_LENGTH:
        # Preserve extension
        name, ext = os.path.splitext(filename)
        max_name_len = MAX_FILENAME_LENGTH - len(ext)
        filename = name[:max_name_len] + ext
    
    return filename or "unknown"


# --- MAGIC BYTE SIGNATURES ---
# File format magic bytes for content validation.
# Each entry: (byte_sequence, offset) - offset is typically 0 for header magic
#
# Sources:
# - https://en.wikipedia.org/wiki/List_of_file_signatures
# - https://www.garykessler.net/library/file_sigs.html
MAGIC_SIGNATURES = {
    # PDF: "%PDF" at start
    "application/pdf": [
        (b"%PDF", 0),
    ],
    
    # Office Open XML (DOCX, XLSX) - ZIP format with specific structure
    # All are ZIP files starting with PK\x03\x04
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [
        (b"PK\x03\x04", 0),
    ],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [
        (b"PK\x03\x04", 0),
    ],
    
    # Legacy Office formats - OLE Compound Document
    "application/msword": [
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 0),  # OLE2 header
    ],
    "application/vnd.ms-excel": [
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 0),  # OLE2 header
    ],
    
    # RTF: "{\rtf" at start
    "application/rtf": [
        (b"{\\rtf", 0),
    ],
    
    # Plain text - no magic bytes, but must be valid UTF-8/ASCII
    # Handled specially in validate_magic_bytes()
    "text/plain": [],
    
    # CSV - no magic bytes, text format
    # Handled specially in validate_magic_bytes()
    "text/csv": [],
    
    # Images
    "image/jpeg": [
        (b"\xFF\xD8\xFF", 0),  # JPEG SOI marker
    ],
    "image/png": [
        (b"\x89PNG\r\n\x1a\n", 0),  # PNG signature
    ],
    "image/gif": [
        (b"GIF87a", 0),
        (b"GIF89a", 0),
    ],
    "image/tiff": [
        (b"II\x2A\x00", 0),  # Little-endian TIFF
        (b"MM\x00\x2A", 0),  # Big-endian TIFF
    ],
    "image/bmp": [
        (b"BM", 0),  # BMP header
    ],
    "image/webp": [
        (b"RIFF", 0),  # WebP is RIFF container (also check for WEBP at offset 8)
    ],
    # HEIC/HEIF - ISO Base Media File Format (ftyp box)
    "image/heic": [
        (b"ftyp", 4),  # ftyp box identifier at offset 4
    ],
}

# Additional check for WebP - must have "WEBP" at offset 8
WEBP_SECONDARY_CHECK = (b"WEBP", 8)


def detect_mime_from_magic_bytes(
    file_content: bytes,
) -> str | None:
    """
    Detect MIME type from file content magic bytes.

    This allows us to determine the actual file type regardless of what
    the browser reported (which is based on extension, not content).

    Args:
        file_content: Raw file bytes

    Returns:
        Detected MIME type, or None if no match found
    """
    if not file_content:
        return None

    header = file_content[:64]  # First 64 bytes is enough for all signatures

    # Check each known MIME type's signatures
    for mime_type, signatures in MAGIC_SIGNATURES.items():
        # Skip text types (no magic bytes)
        if mime_type in ("text/plain", "text/csv"):
            continue

        if not signatures:
            continue

        for signature, offset in signatures:
            if len(header) >= offset + len(signature):
                if header[offset:offset + len(signature)] == signature:
                    # Additional check for WebP
                    if mime_type == "image/webp":
                        webp_sig, webp_offset = WEBP_SECONDARY_CHECK
                        if len(header) >= webp_offset + len(webp_sig):
                            if header[webp_offset:webp_offset + len(webp_sig)] != webp_sig:
                                continue  # Not actually WebP, check other types
                    return mime_type

    # Check if it might be text (no null bytes, valid UTF-8)
    if _validate_text_content(file_content):
        # Could be text/plain or text/csv - return text/plain as default
        return "text/plain"

    return None


def validate_magic_bytes(
    expected_mime: str,
    file_path: Optional[Union[str, Path]] = None,
    file_content: Optional[bytes] = None,
) -> bool:
    """
    Validate file content matches expected MIME type via magic bytes.
    
    This prevents attacks where malicious files are renamed to bypass
    extension/MIME checks.
    
    Args:
        expected_mime: Expected MIME type based on extension/Content-Type
        file_path: Path to the file to validate (reads from disk)
        file_content: Raw file bytes to validate (in-memory validation)
        
    Note: Provide either file_path OR file_content, not both.
        
    Returns:
        True if magic bytes match expected type, False otherwise
        
    Raises:
        FileValidationError: If file cannot be read or is invalid
        ValueError: If neither file_path nor file_content provided
    """
    # Get the header bytes to check
    if file_content is not None:
        header = file_content[:64]  # First 64 bytes is enough for all signatures
        source_name = "<memory>"
    elif file_path is not None:
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileValidationError(f"File not found: {file_path}")
        try:
            with open(file_path, "rb") as f:
                header = f.read(64)
        except IOError as e:
            raise FileValidationError(f"Cannot read file for validation: {e}")
        source_name = file_path.name
    else:
        raise ValueError("Must provide either file_path or file_content")
    
    if len(header) == 0:
        raise FileValidationError("File is empty")
    
    # Get expected signatures
    signatures = MAGIC_SIGNATURES.get(expected_mime)
    
    if signatures is None:
        # Unknown MIME type - log warning but allow (fail open for unknown types)
        logger.warning(f"No magic signature defined for MIME type: {expected_mime}")
        return True
    
    # Special handling for text formats (no magic bytes)
    if expected_mime in ("text/plain", "text/csv"):
        if file_content is not None:
            return _validate_text_content(file_content)
        else:
            return _validate_text_file(file_path)
    
    # Empty signature list means type has no magic bytes but isn't text
    if not signatures:
        logger.warning(f"No magic signatures for {expected_mime}, skipping validation")
        return True
    
    # Check each possible signature
    for signature, offset in signatures:
        if len(header) >= offset + len(signature):
            if header[offset:offset + len(signature)] == signature:
                # Additional check for WebP
                if expected_mime == "image/webp":
                    webp_sig, webp_offset = WEBP_SECONDARY_CHECK
                    if len(header) >= webp_offset + len(webp_sig):
                        if header[webp_offset:webp_offset + len(webp_sig)] != webp_sig:
                            continue  # Not actually WebP
                return True
    
    # No signature matched
    logger.warning(
        f"Magic byte mismatch for {source_name}: "
        f"expected {expected_mime}, got header {header[:16].hex()}"
    )
    return False


def _validate_text_content(content: bytes, sample_size: int = 8192) -> bool:
    """
    Validate that bytes content is actually text (UTF-8 or ASCII).
    
    Checks for:
    - Valid UTF-8 encoding
    - No null bytes (binary indicator)
    - Reasonable character distribution
    
    Args:
        content: Raw bytes to validate
        sample_size: Bytes to sample for validation
        
    Returns:
        True if content appears to be valid text
    """
    sample = content[:sample_size]
    
    if not sample:
        return True  # Empty content is valid text
    
    # Check for null bytes (strong binary indicator)
    if b"\x00" in sample:
        logger.warning("Null bytes found in alleged text content")
        return False
    
    # Try to decode as UTF-8
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        # Try Latin-1 as fallback (accepts any byte sequence)
        try:
            sample.decode("latin-1")
            # Check for high ratio of non-printable characters
            non_printable = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))
            if non_printable / len(sample) > 0.1:  # >10% non-printable
                logger.warning("High non-printable ratio in text content")
                return False
            return True
        except (UnicodeDecodeError, LookupError):
            return False


def _validate_text_file(file_path: Path, sample_size: int = 8192) -> bool:
    """
    Validate that a file is actually text (UTF-8 or ASCII).
    
    Reads a sample of the file and checks for:
    - Valid UTF-8 encoding
    - No null bytes (binary indicator)
    - Reasonable character distribution
    
    Args:
        file_path: Path to file
        sample_size: Bytes to sample for validation
        
    Returns:
        True if file appears to be valid text
    """
    try:
        with open(file_path, "rb") as f:
            sample = f.read(sample_size)
        
        if not sample:
            return True  # Empty file is valid text
        
        # Check for null bytes (strong binary indicator)
        if b"\x00" in sample:
            logger.warning(f"Null bytes found in alleged text file: {file_path.name}")
            return False
        
        # Try to decode as UTF-8
        try:
            sample.decode("utf-8")
            return True
        except UnicodeDecodeError:
            # Try Latin-1 as fallback (accepts any byte sequence)
            # But warn - could be binary
            try:
                sample.decode("latin-1")
                # Check for high ratio of non-printable characters
                non_printable = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))
                if non_printable / len(sample) > 0.1:  # >10% non-printable
                    logger.warning(f"High non-printable ratio in text file: {file_path.name}")
                    return False
                return True
            except (UnicodeDecodeError, LookupError):
                return False
                
    except IOError as e:
        raise FileValidationError(f"Cannot read file for text validation: {e}")


# --- ALLOWED FILE TYPES ---
# Allowed file types with constraints
# Format: MIME type -> {extensions, max size in MB, optional page/row limits}
ALLOWED_TYPES = {
    # Documents
    "application/pdf": {
        "ext": [".pdf"],
        "max_mb": 50,
        "max_pages": 500,
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
        "ext": [".docx"],
        "max_mb": 25,
    },
    "application/msword": {
        "ext": [".doc"],
        "max_mb": 25,
    },
    "application/rtf": {
        "ext": [".rtf"],
        "max_mb": 10,
    },
    "text/plain": {
        "ext": [".txt"],
        "max_mb": 5,
    },
    
    # Spreadsheets
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
        "ext": [".xlsx"],
        "max_mb": 25,
        "max_rows": 50000,
    },
    "application/vnd.ms-excel": {
        "ext": [".xls"],
        "max_mb": 25,
    },
    "text/csv": {
        "ext": [".csv"],
        "max_mb": 10,
    },
    
    # Images
    "image/jpeg": {
        "ext": [".jpg", ".jpeg"],
        "max_mb": 20,
    },
    "image/png": {
        "ext": [".png"],
        "max_mb": 20,
    },
    "image/tiff": {
        "ext": [".tiff", ".tif"],
        "max_mb": 50,
    },
    "image/heic": {
        "ext": [".heic", ".heif"],
        "max_mb": 20,
    },
    "image/gif": {
        "ext": [".gif"],
        "max_mb": 10,
    },
    "image/bmp": {
        "ext": [".bmp"],
        "max_mb": 20,
    },
    "image/webp": {
        "ext": [".webp"],
        "max_mb": 20,
    },
}

# Reverse lookup: extension -> MIME types
EXTENSION_TO_MIME = {}
for mime, config in ALLOWED_TYPES.items():
    for ext in config["ext"]:
        if ext not in EXTENSION_TO_MIME:
            EXTENSION_TO_MIME[ext] = []
        EXTENSION_TO_MIME[ext].append(mime)


def get_extension(filename: str) -> str:
    """Get lowercase extension from filename."""
    return Path(filename).suffix.lower()


def is_allowed_extension(filename: str) -> bool:
    """Check if file extension is allowed."""
    ext = get_extension(filename)
    return ext in EXTENSION_TO_MIME


def is_allowed_mime(content_type: str) -> bool:
    """Check if MIME type is allowed."""
    # Normalize MIME type (strip charset etc)
    mime = content_type.split(";")[0].strip().lower()
    return mime in ALLOWED_TYPES


def get_max_size_bytes(content_type: str) -> int:
    """Get maximum allowed size in bytes for MIME type."""
    mime = content_type.split(";")[0].strip().lower()
    config = ALLOWED_TYPES.get(mime, {})
    max_mb = config.get("max_mb", 50)  # Default 50MB
    return max_mb * 1024 * 1024


def validate_file(
    filename: str,
    content_type: Optional[str],
    size_bytes: int,
    file_path: Optional[Union[str, Path]] = None,
    file_content: Optional[bytes] = None,
) -> str | None:
    """
    Validate file before processing.

    Performs three-layer validation:
    1. Extension check - is the file type allowed?
    2. MIME type check - does Content-Type match extension?
    3. Magic byte check - does file content match claimed type?

    Args:
        filename: Original filename
        content_type: MIME type from upload
        size_bytes: File size in bytes
        file_path: Path to saved file for magic byte validation (optional)
        file_content: Raw file bytes for magic byte validation (optional)

    Note: For magic byte validation, provide either file_path OR file_content.
          If neither is provided, magic byte validation is skipped.

    Returns:
        The validated/corrected MIME type. If actual content differs from claimed
        type but is still allowed, returns the detected type from magic bytes.
        Returns None if type cannot be determined.

    Raises:
        FileValidationError: If validation fails
    """
    # 1. Check extension
    ext = get_extension(filename)
    if not ext:
        raise FileValidationError(f"File has no extension: {filename}")
    
    if ext not in EXTENSION_TO_MIME:
        allowed = ", ".join(sorted(EXTENSION_TO_MIME.keys()))
        raise FileValidationError(
            f"File type '{ext}' not allowed. Allowed: {allowed}"
        )
    
    # 2. Check MIME type if provided
    if content_type:
        mime = content_type.split(";")[0].strip().lower()
        
        if mime not in ALLOWED_TYPES:
            raise FileValidationError(
                f"MIME type '{mime}' not allowed for file: {filename}"
            )
        
        # Check extension matches MIME type
        config = ALLOWED_TYPES[mime]
        if ext not in config["ext"]:
            raise FileValidationError(
                f"Extension '{ext}' does not match MIME type '{mime}'"
            )
        
        # Use MIME-specific size limit
        max_bytes = config["max_mb"] * 1024 * 1024
    else:
        # Infer MIME from extension
        mime = EXTENSION_TO_MIME.get(ext, [None])[0]
        
        # Fall back to extension-based limits
        possible_mimes = EXTENSION_TO_MIME.get(ext, [])
        if possible_mimes:
            # Use the largest limit among possible MIME types
            max_bytes = max(
                ALLOWED_TYPES[m]["max_mb"] * 1024 * 1024 
                for m in possible_mimes
            )
        else:
            max_bytes = MAX_FILE_SIZE_BYTES
    
    # 3. Check size
    if size_bytes > max_bytes:
        max_mb = max_bytes / (1024 * 1024)
        actual_mb = size_bytes / (1024 * 1024)
        raise FileValidationError(
            f"File too large: {actual_mb:.1f}MB exceeds limit of {max_mb:.0f}MB"
        )
    
    if size_bytes == 0:
        raise FileValidationError("File is empty")
    
    # 4. SECURITY: Validate magic bytes if file path or content provided
    if file_path is not None or file_content is not None:
        claimed_mime = mime if content_type else EXTENSION_TO_MIME.get(ext, [None])[0]

        # Detect actual MIME type from file content
        if file_content is not None:
            actual_mime = detect_mime_from_magic_bytes(file_content)
        else:
            # Check file exists before reading
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileValidationError(f"File not found: {file_path}")
            # Read file content for detection
            with open(file_path, "rb") as f:
                actual_mime = detect_mime_from_magic_bytes(f.read(64))

        # SECURITY: If actual type differs from claimed type, reject as spoofing
        # This prevents attackers from uploading malicious files by claiming
        # a different extension/Content-Type
        if actual_mime and actual_mime != claimed_mime:
            raise FileValidationError(
                f"File content does not match claimed type. "
                f"Claimed: '{claimed_mime}', Actual: '{actual_mime}'. "
                f"Possible file type spoofing detected."
            )
        elif claimed_mime:
            # Claimed and actual match (or can't detect actual) - validate normally
            if not validate_magic_bytes(
                expected_mime=claimed_mime,
                file_path=file_path,
                file_content=file_content,
            ):
                raise FileValidationError(
                    f"File content does not match expected type '{claimed_mime}'. "
                    f"Possible file type spoofing detected."
                )
    
    logger.debug(
        f"File validated: {filename} ({size_bytes} bytes, {mime or content_type})"
    )

    return mime


def validate_uploaded_file(
    filename: str,
    content_type: Optional[str],
    file_path: Union[str, Path],
) -> None:
    """
    Convenience function to validate an uploaded file that's already saved.
    
    Combines size check with magic byte validation.
    
    Args:
        filename: Original filename
        content_type: MIME type from upload
        file_path: Path where file is saved
        
    Raises:
        FileValidationError: If validation fails
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileValidationError(f"File not found: {file_path}")
    
    size_bytes = file_path.stat().st_size
    
    validate_file(
        filename=filename,
        content_type=content_type,
        size_bytes=size_bytes,
        file_path=file_path,
    )


def infer_content_type(filename: str) -> Optional[str]:
    """
    Infer MIME type from filename extension.
    
    Returns first matching MIME type, or None if unknown.
    """
    ext = get_extension(filename)
    mimes = EXTENSION_TO_MIME.get(ext, [])
    return mimes[0] if mimes else None


def is_image(content_type: str) -> bool:
    """Check if content type is an image."""
    mime = content_type.split(";")[0].strip().lower()
    return mime.startswith("image/")


def is_pdf(content_type: str) -> bool:
    """Check if content type is PDF."""
    mime = content_type.split(";")[0].strip().lower()
    return mime == "application/pdf"


def is_spreadsheet(content_type: str) -> bool:
    """Check if content type is a spreadsheet."""
    mime = content_type.split(";")[0].strip().lower()
    spreadsheet_types = {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel",
        "text/csv",
    }
    return mime in spreadsheet_types


def is_document(content_type: str) -> bool:
    """Check if content type is a document (Word, RTF, TXT)."""
    mime = content_type.split(";")[0].strip().lower()
    doc_types = {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/msword",
        "application/rtf",
        "text/plain",
    }
    return mime in doc_types
