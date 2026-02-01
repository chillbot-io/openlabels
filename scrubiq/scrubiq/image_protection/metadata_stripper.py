"""
Metadata Stripping for ScrubIQ.

Removes all metadata from files to prevent PHI leakage through EXIF, XMP,
document properties, and other embedded data.

CRITICAL: EXIF thumbnails can contain the ORIGINAL unredacted image.
This module strips thumbnails along with all other metadata.

HIPAA Safe Harbor implications:
- GPS coordinates can reveal patient location
- Device serial numbers are PHI
- Author/creator fields often contain names
- Timestamps can be PHI when linked to medical events
- Thumbnails may contain unredacted faces

Philosophy: Strip everything. Don't try to identify PHI in metadata -
just remove ALL metadata. The only safe metadata is no metadata.

Supported formats:
- Images: JPEG, PNG, TIFF, WebP, GIF, BMP
- Documents: PDF, DOCX, XLSX, PPTX
- Special: DICOM awareness (warns but doesn't process)

Usage:
    stripper = MetadataStripper()
    clean_bytes, result = stripper.strip(file_bytes, filename)
"""

import hashlib
import io
import logging
import struct
import time
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

# SECURITY: Use defusedxml to prevent XXE attacks
# Standard xml.etree.ElementTree is vulnerable to XML External Entity attacks
# which could allow attackers to read arbitrary files from the server
try:
    import defusedxml.ElementTree as ET
except ImportError:
    # Fallback with warning - should not happen in production
    import xml.etree.ElementTree as ET
    import warnings
    warnings.warn(
        "defusedxml not installed - XML parsing may be vulnerable to XXE attacks. "
        "Install with: pip install defusedxml",
        SecurityWarning,
    )

logger = logging.getLogger(__name__)


# DATA TYPES

class FileType(Enum):
    """Detected file types."""
    JPEG = "jpeg"
    PNG = "png"
    TIFF = "tiff"
    WEBP = "webp"
    GIF = "gif"
    BMP = "bmp"
    PDF = "pdf"
    DOCX = "docx"
    XLSX = "xlsx"
    PPTX = "pptx"
    DICOM = "dicom"
    UNKNOWN = "unknown"


@dataclass
class MetadataField:
    """A single metadata field that was found and removed."""
    category: str       # e.g., "EXIF", "XMP", "Office", "PDF"
    name: str          # e.g., "GPS", "Author", "Creator"
    is_sensitive: bool  # True if field is known to contain PHI-risk data
    
    def __str__(self) -> str:
        return f"{self.category}:{self.name}"


@dataclass
class MetadataStrippingResult:
    """Result of metadata stripping operation."""
    original_hash: str
    stripped_hash: str
    file_type: FileType
    fields_removed: List[MetadataField]
    processing_time_ms: float
    
    # Critical flags
    had_thumbnail: bool = False      # EXIF thumbnail was present (high risk)
    had_gps: bool = False           # GPS coordinates were present
    had_device_id: bool = False     # Device identifiers were present
    had_author: bool = False        # Author/creator fields were present
    had_timestamps: bool = False    # Date/time fields were present
    
    # Warnings
    warnings: List[str] = field(default_factory=list)
    
    @property
    def total_fields_removed(self) -> int:
        return len(self.fields_removed)
    
    @property
    def sensitive_fields_removed(self) -> int:
        return sum(1 for f in self.fields_removed if f.is_sensitive)
    
    def to_audit_dict(self) -> dict:
        """Convert to audit-safe dict."""
        return {
            "original_hash": self.original_hash,
            "stripped_hash": self.stripped_hash,
            "file_type": self.file_type.value,
            "total_fields_removed": self.total_fields_removed,
            "sensitive_fields_removed": self.sensitive_fields_removed,
            "had_thumbnail": self.had_thumbnail,
            "had_gps": self.had_gps,
            "had_device_id": self.had_device_id,
            "had_author": self.had_author,
            "processing_time_ms": round(self.processing_time_ms, 1),
            "warnings": self.warnings,
        }


# SENSITIVE FIELD DEFINITIONS

# EXIF tags that are sensitive (PHI risk)
SENSITIVE_EXIF_TAGS = {
    # GPS tags
    "GPSInfo", "GPSLatitude", "GPSLongitude", "GPSAltitude",
    "GPSLatitudeRef", "GPSLongitudeRef", "GPSTimeStamp", "GPSDateStamp",
    # Device identification
    "Make", "Model", "Software", "HostComputer", "BodySerialNumber",
    "LensSerialNumber", "CameraSerialNumber", "SerialNumber",
    "ImageUniqueID", "CameraOwnerName", "OwnerName",
    # Creator/Author
    "Artist", "Copyright", "Author", "Creator",
    # Dates (can be PHI when linked to medical events)
    "DateTime", "DateTimeOriginal", "DateTimeDigitized",
    "CreateDate", "ModifyDate",
    # Location/Description
    "ImageDescription", "UserComment", "XPComment", "XPAuthor", "XPKeywords",
    # Thumbnail (CRITICAL - may contain unredacted original)
    "ThumbnailImage", "JPEGThumbnail", "TIFFThumbnail",
}

# XMP fields that are sensitive
SENSITIVE_XMP_FIELDS = {
    "creator", "author", "title", "description", "subject",
    "rights", "creator-tool", "createdate", "modifydate",
    "metadatadate", "gps", "location",
}

# Office document fields that are sensitive
SENSITIVE_OFFICE_FIELDS = {
    "creator", "lastmodifiedby", "author", "manager", "company",
    "title", "subject", "keywords", "description", "category",
    "revision", "created", "modified", "lastprinted",
}


# FILE TYPE DETECTION

def detect_file_type(data: bytes) -> FileType:
    """
    Detect file type by magic bytes (not extension).
    
    Using magic bytes is more reliable than extensions and prevents
    bypass attacks using renamed files.
    """
    if len(data) < 12:
        return FileType.UNKNOWN
    
    # JPEG: FF D8 FF
    if data[:3] == b'\xff\xd8\xff':
        return FileType.JPEG
    
    # PNG: 89 50 4E 47 0D 0A 1A 0A
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return FileType.PNG
    
    # TIFF: II*\x00 (little-endian) or MM\x00* (big-endian)
    if data[:4] in (b'II*\x00', b'MM\x00*'):
        return FileType.TIFF
    
    # WebP: RIFF....WEBP
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return FileType.WEBP
    
    # GIF: GIF87a or GIF89a
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return FileType.GIF
    
    # BMP: BM
    if data[:2] == b'BM':
        return FileType.BMP
    
    # PDF: %PDF
    if data[:4] == b'%PDF':
        return FileType.PDF
    
    # Office Open XML (ZIP-based): PK\x03\x04
    if data[:4] == b'PK\x03\x04':
        # Need to peek inside to determine specific format
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                if any('word/' in n for n in names):
                    return FileType.DOCX
                elif any('xl/' in n for n in names):
                    return FileType.XLSX
                elif any('ppt/' in n for n in names):
                    return FileType.PPTX
        except (zipfile.BadZipFile, IOError, KeyError):
            pass
        return FileType.UNKNOWN
    
    # DICOM: DICM at offset 128
    if len(data) > 132 and data[128:132] == b'DICM':
        return FileType.DICOM
    
    return FileType.UNKNOWN


# METADATA STRIPPER

class MetadataStripper:
    """
    Remove all metadata from files.
    
    This is a defense-in-depth measure - even if we think a field is safe,
    we remove it. Unknown fields could contain PHI, and the safest approach
    is complete removal.
    
    Special handling:
    - JPEG: Removes all APP markers (EXIF, XMP, IPTC, ICC profiles, thumbnails)
    - PNG: Removes all ancillary chunks (tEXt, iTXt, zTXt, etc.)
    - PDF: Removes /Info dictionary and XMP metadata
    - Office: Removes docProps/core.xml, docProps/app.xml, custom properties
    """
    
    def __init__(self, preserve_color_profile: bool = False):
        """
        Initialize metadata stripper.
        
        Args:
            preserve_color_profile: If True, keep ICC color profiles.
                                    Usually False for maximum safety.
        """
        self.preserve_color_profile = preserve_color_profile
    
    def strip(
        self,
        data: bytes,
        filename: str = "",
    ) -> Tuple[bytes, MetadataStrippingResult]:
        """
        Strip all metadata from file.
        
        Args:
            data: File bytes
            filename: Original filename (for logging only)
            
        Returns:
            Tuple of (stripped_bytes, MetadataStrippingResult)
        """
        start_time = time.perf_counter()
        
        # Hash original
        original_hash = hashlib.sha256(data).hexdigest()[:16]
        
        # Detect file type
        file_type = detect_file_type(data)
        
        # Initialize result
        fields_removed: List[MetadataField] = []
        warnings: List[str] = []
        
        # Route to appropriate handler
        if file_type == FileType.JPEG:
            stripped, fields_removed = self._strip_jpeg(data)
        elif file_type == FileType.PNG:
            stripped, fields_removed = self._strip_png(data)
        elif file_type == FileType.TIFF:
            stripped, fields_removed = self._strip_tiff(data)
        elif file_type == FileType.WEBP:
            stripped, fields_removed = self._strip_webp(data)
        elif file_type == FileType.GIF:
            stripped, fields_removed = self._strip_gif(data)
        elif file_type == FileType.BMP:
            # BMP has minimal metadata, but we still re-encode
            stripped, fields_removed = self._strip_bmp(data)
        elif file_type == FileType.PDF:
            stripped, fields_removed = self._strip_pdf(data)
        elif file_type in (FileType.DOCX, FileType.XLSX, FileType.PPTX):
            stripped, fields_removed = self._strip_office(data, file_type)
        elif file_type == FileType.DICOM:
            # DICOM requires specialized handling - warn but pass through
            warnings.append(
                "DICOM file detected. DICOM requires specialized de-identification. "
                "Use a dedicated DICOM anonymizer (e.g., RSNA CTP, deid)."
            )
            stripped = data
        else:
            # SECURITY: Unknown file types may contain metadata with PHI
            # Log at WARNING level and include in warnings for visibility
            logger.warning(
                f"Unknown file type detected, metadata NOT stripped. "
                f"File may contain PHI in metadata. Original hash: {original_hash}"
            )
            warnings.append(
                "SECURITY WARNING: Unknown file type, metadata not stripped. "
                "File may contain embedded PHI (GPS, device IDs, author info, etc.)"
            )
            stripped = data
        
        processing_time = (time.perf_counter() - start_time) * 1000
        stripped_hash = hashlib.sha256(stripped).hexdigest()[:16]
        
        # Analyze what was removed
        result = MetadataStrippingResult(
            original_hash=original_hash,
            stripped_hash=stripped_hash,
            file_type=file_type,
            fields_removed=fields_removed,
            processing_time_ms=processing_time,
            had_thumbnail=any("thumbnail" in f.name.lower() for f in fields_removed),
            had_gps=any("gps" in f.name.lower() for f in fields_removed),
            had_device_id=any(
                any(kw in f.name.lower() for kw in ("make", "model", "serialnumber", "bodyserialnumber"))
                for f in fields_removed
            ),
            had_author=any(
                any(kw in f.name.lower() for kw in ("author", "creator", "artist", "lastmodifiedby"))
                for f in fields_removed
            ),
            had_timestamps=any(
                "date" in f.name.lower() or "time" in f.name.lower()
                for f in fields_removed
            ),
            warnings=warnings,
        )
        
        if fields_removed:
            logger.info(
                f"Stripped {len(fields_removed)} metadata fields from {filename or 'file'} "
                f"({file_type.value}): thumbnail={result.had_thumbnail}, "
                f"gps={result.had_gps}, author={result.had_author}"
            )
        
        return stripped, result
    # JPEG HANDLING
    def _strip_jpeg(self, data: bytes) -> Tuple[bytes, List[MetadataField]]:
        """
        Strip metadata from JPEG by removing APP markers.
        
        JPEG structure:
        - SOI (FF D8)
        - APP0-APP15 markers (FF E0 - FF EF) - contain EXIF, XMP, etc.
        - Other markers (DQT, DHT, SOF, SOS, etc.)
        - Image data
        - EOI (FF D9)
        
        We keep only: SOI, DQT, DHT, SOF, DRI, SOS, RST, and EOI
        We remove: APP0-APP15 (EXIF, XMP, JFIF), COM (comments)
        """
        fields = []
        
        # Use PIL for reliable handling
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            img = Image.open(io.BytesIO(data))
            
            # Record what we're removing
            exif = img.getexif() if hasattr(img, 'getexif') else None
            if exif:
                for tag_id, value in exif.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    is_sensitive = tag_name in SENSITIVE_EXIF_TAGS
                    fields.append(MetadataField("EXIF", tag_name, is_sensitive))
                    
                    # Check for GPS sub-IFD
                    if tag_name == "GPSInfo" and isinstance(value, dict):
                        fields.append(MetadataField("EXIF", "GPSData", True))
                
                # Check for thumbnail
                try:
                    thumb = exif.get_thumbnail()
                    if thumb:
                        fields.append(MetadataField("EXIF", "ThumbnailImage", True))
                except (AttributeError, KeyError, TypeError):
                    pass
            
            # Check for XMP
            if hasattr(img, 'info') and 'xmp' in img.info:
                fields.append(MetadataField("XMP", "XMPPacket", True))
            
            # Check for IPTC
            if hasattr(img, 'info') and 'photoshop' in img.info:
                fields.append(MetadataField("IPTC", "PhotoshopData", True))
            
            # Check for ICC profile
            if hasattr(img, 'info') and 'icc_profile' in img.info:
                fields.append(MetadataField("ICC", "ColorProfile", False))
            
            # Recreate image without metadata
            # This is the nuclear option but guarantees clean output
            output = io.BytesIO()

            # Get pixel data via numpy to avoid deprecated getdata()
            import numpy as np
            pixel_data = np.array(img)
            clean_img = Image.fromarray(pixel_data)
            
            # Save without EXIF, preserving quality
            # Use quality=95 to balance size and quality
            clean_img.save(output, format='JPEG', quality=95, subsampling='4:4:4')
            
            return output.getvalue(), fields
            
        except ImportError:
            logger.warning("PIL not available, using manual JPEG stripping")
            return self._strip_jpeg_manual(data)
        except Exception as e:
            logger.error(f"PIL JPEG stripping failed: {e}, using manual method")
            return self._strip_jpeg_manual(data)
    
    def _strip_jpeg_manual(self, data: bytes) -> Tuple[bytes, List[MetadataField]]:
        """
        Manual JPEG metadata stripping without PIL.
        
        Removes APP and COM markers while preserving image data.
        """
        fields = []
        
        if len(data) < 4 or data[:2] != b'\xff\xd8':
            return data, fields
        
        output = io.BytesIO()
        output.write(b'\xff\xd8')  # SOI
        
        pos = 2
        
        while pos < len(data) - 1:
            if data[pos] != 0xff:
                pos += 1
                continue
            
            marker = data[pos + 1]
            
            # Skip padding FF bytes
            if marker == 0xff:
                pos += 1
                continue
            
            # End of image
            if marker == 0xd9:
                output.write(b'\xff\xd9')
                break
            
            # Markers without length (RST0-RST7, SOI, EOI)
            if marker in (0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0x01):
                output.write(data[pos:pos+2])
                pos += 2
                continue
            
            # Read marker length
            if pos + 4 > len(data):
                break
            
            length = struct.unpack('>H', data[pos+2:pos+4])[0]
            
            # APP markers (E0-EF) and COM (FE) - skip these
            if 0xe0 <= marker <= 0xef or marker == 0xfe:
                marker_names = {
                    0xe0: "JFIF", 0xe1: "EXIF/XMP", 0xe2: "ICC",
                    0xed: "IPTC", 0xfe: "Comment"
                }
                name = marker_names.get(marker, f"APP{marker - 0xe0}")
                fields.append(MetadataField("JPEG", name, marker in (0xe1, 0xed, 0xfe)))
                pos += 2 + length
                continue
            
            # Keep all other markers (DQT, DHT, SOF, SOS, etc.)
            output.write(data[pos:pos + 2 + length])
            
            # SOS marker is followed by image data until next marker
            if marker == 0xda:
                pos += 2 + length
                # Copy until we hit FFD9 (EOI) or another marker
                while pos < len(data) - 1:
                    if data[pos] == 0xff and data[pos + 1] != 0x00:
                        # Found a marker (not stuffed byte)
                        break
                    output.write(bytes([data[pos]]))
                    pos += 1
                continue
            
            pos += 2 + length
        
        return output.getvalue(), fields
    # PNG HANDLING
    def _strip_png(self, data: bytes) -> Tuple[bytes, List[MetadataField]]:
        """
        Strip metadata from PNG by removing ancillary chunks.
        
        PNG chunks:
        - Critical (must keep): IHDR, PLTE, IDAT, IEND
        - Ancillary (remove): tEXt, iTXt, zTXt, tIME, eXIf, etc.
        
        We keep only critical chunks and optionally iCCP (color profile).
        """
        fields = []
        
        if len(data) < 8 or data[:8] != b'\x89PNG\r\n\x1a\n':
            return data, fields
        
        # Critical chunks to preserve
        critical_chunks = {b'IHDR', b'PLTE', b'IDAT', b'IEND'}
        
        # Optional: preserve color profile
        if self.preserve_color_profile:
            critical_chunks.add(b'iCCP')
            critical_chunks.add(b'sRGB')
            critical_chunks.add(b'gAMA')
            critical_chunks.add(b'cHRM')
        
        output = io.BytesIO()
        output.write(data[:8])  # PNG signature
        
        pos = 8
        
        while pos < len(data) - 4:
            # Read chunk length
            if pos + 8 > len(data):
                break
            
            chunk_length = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            chunk_end = pos + 12 + chunk_length  # length + type + data + CRC
            
            if chunk_end > len(data):
                break
            
            chunk_data = data[pos:chunk_end]
            
            if chunk_type in critical_chunks:
                output.write(chunk_data)
            else:
                # Record removed chunk
                chunk_name = chunk_type.decode('ascii', errors='replace')
                is_sensitive = chunk_name.lower() in ('text', 'itxt', 'ztxt', 'exif', 'time')
                fields.append(MetadataField("PNG", chunk_name, is_sensitive))
            
            pos = chunk_end
        
        return output.getvalue(), fields
    # TIFF HANDLING
    def _strip_tiff(self, data: bytes) -> Tuple[bytes, List[MetadataField]]:
        """
        Strip metadata from TIFF.
        
        TIFF is complex - we use PIL to recreate without metadata.
        """
        fields = []
        
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            img = Image.open(io.BytesIO(data))
            
            # Record TIFF tags
            if hasattr(img, 'tag_v2'):
                for tag_id in img.tag_v2:
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    is_sensitive = tag_name in SENSITIVE_EXIF_TAGS
                    fields.append(MetadataField("TIFF", tag_name, is_sensitive))
            
            # Recreate without metadata (using numpy to avoid Pillow deprecation)
            import numpy as np
            pixel_data = np.array(img)
            clean_img = Image.fromarray(pixel_data)

            output = io.BytesIO()
            clean_img.save(output, format='TIFF')
            
            return output.getvalue(), fields
            
        except Exception as e:
            logger.warning(f"TIFF stripping failed: {e}, returning original")
            return data, fields
    # WEBP HANDLING
    def _strip_webp(self, data: bytes) -> Tuple[bytes, List[MetadataField]]:
        """Strip metadata from WebP."""
        fields = []
        
        try:
            from PIL import Image
            
            img = Image.open(io.BytesIO(data))
            
            # Check for EXIF
            exif = img.getexif() if hasattr(img, 'getexif') else None
            if exif:
                for tag_id in exif:
                    from PIL.ExifTags import TAGS
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    fields.append(MetadataField("EXIF", tag_name, tag_name in SENSITIVE_EXIF_TAGS))
            
            # Check for XMP
            if hasattr(img, 'info') and 'xmp' in img.info:
                fields.append(MetadataField("XMP", "XMPPacket", True))

            # Recreate (using numpy to avoid Pillow deprecation)
            import numpy as np
            pixel_data = np.array(img)
            clean_img = Image.fromarray(pixel_data)

            output = io.BytesIO()
            clean_img.save(output, format='WEBP', quality=95)
            
            return output.getvalue(), fields
            
        except Exception as e:
            logger.warning(f"WebP stripping failed: {e}, returning original")
            return data, fields
    # GIF HANDLING
    def _strip_gif(self, data: bytes) -> Tuple[bytes, List[MetadataField]]:
        """Strip metadata from GIF (comments and application extensions).

        GIF comments can contain PHI - they must be removed.
        PIL preserves comments in img.info by default when saving,
        so we must explicitly remove them before saving.
        """
        fields = []

        try:
            from PIL import Image

            img = Image.open(io.BytesIO(data))

            # Check for and remove comments from info dict
            # PIL will include comment in output if present in img.info
            if hasattr(img, 'info') and 'comment' in img.info:
                fields.append(MetadataField("GIF", "Comment", True))
                del img.info['comment']  # Remove to prevent re-embedding

            # Remove any XMP data that might be present
            if hasattr(img, 'info') and 'xmp' in img.info:
                fields.append(MetadataField("GIF", "XMP", True))
                del img.info['xmp']

            # For animated GIFs, we need special handling
            # For now, just recreate the first frame
            output = io.BytesIO()
            img.save(output, format='GIF')

            return output.getvalue(), fields

        except Exception as e:
            logger.warning(f"GIF stripping failed: {e}, returning original")
            return data, fields
    # BMP HANDLING
    def _strip_bmp(self, data: bytes) -> Tuple[bytes, List[MetadataField]]:
        """Strip metadata from BMP (minimal metadata, but re-encode anyway)."""
        fields = []
        
        try:
            from PIL import Image
            
            img = Image.open(io.BytesIO(data))
            
            output = io.BytesIO()
            img.save(output, format='BMP')
            
            return output.getvalue(), fields
            
        except Exception as e:
            logger.warning(f"BMP stripping failed: {e}, returning original")
            return data, fields
    # PDF HANDLING
    def _strip_pdf(self, data: bytes) -> Tuple[bytes, List[MetadataField]]:
        """
        Strip metadata from PDF.
        
        Removes:
        - /Info dictionary (Author, Creator, Title, Subject, etc.)
        - XMP metadata stream
        - Custom metadata
        
        Uses pikepdf for reliable handling.
        """
        fields = []
        pdf = None

        try:
            import pikepdf

            pdf = pikepdf.open(io.BytesIO(data))

            # Remove document info dictionary
            if '/Info' in pdf.trailer:
                info = pdf.trailer['/Info']
                if isinstance(info, pikepdf.Dictionary):
                    for key in list(info.keys()):
                        key_name = str(key).lstrip('/')
                        is_sensitive = key_name.lower() in (
                            'author', 'creator', 'producer', 'title',
                            'subject', 'keywords', 'creationdate', 'moddate'
                        )
                        fields.append(MetadataField("PDF", f"Info:{key_name}", is_sensitive))

                del pdf.trailer['/Info']

            # Remove XMP metadata
            try:
                with pdf.open_metadata() as meta:
                    # Get list of XMP fields before clearing
                    for key in list(meta.keys()):
                        key_name = key.split('}')[-1] if '}' in key else key
                        is_sensitive = key_name.lower() in SENSITIVE_XMP_FIELDS
                        fields.append(MetadataField("XMP", key_name, is_sensitive))

                    # Clear all XMP
                    # Note: pikepdf's metadata interface is complex,
                    # we need to delete individual keys
            except Exception:
                pass  # XMP access can fail for various reasons

            # Remove metadata from root
            if '/Metadata' in pdf.Root:
                fields.append(MetadataField("PDF", "RootMetadata", True))
                del pdf.Root['/Metadata']

            # Save
            output = io.BytesIO()
            pdf.save(output)

            return output.getvalue(), fields

        except ImportError:
            logger.warning("pikepdf not available, using basic PDF stripping")
            return self._strip_pdf_basic(data)
        except Exception as e:
            logger.error(f"PDF stripping failed: {e}")
            return data, fields
        finally:
            # RESOURCE CLEANUP: Always close pikepdf object to prevent resource leaks
            if pdf is not None:
                try:
                    pdf.close()
                except Exception:
                    pass  # Ignore close errors
    
    def _strip_pdf_basic(self, data: bytes) -> Tuple[bytes, List[MetadataField]]:
        """
        Basic PDF metadata stripping without pikepdf.
        
        This is a best-effort approach that may not catch all metadata.
        """
        # This is complex to do correctly without a proper PDF library
        # For now, just warn and return original
        return data, [MetadataField("PDF", "Warning", False)]
    # OFFICE DOCUMENT HANDLING

    # SECURITY: Zip bomb protection constants
    MAX_DECOMPRESSED_SIZE = 200 * 1024 * 1024  # 200MB max total decompressed size
    MAX_EXTRACTION_RATIO = 100  # Max ratio of decompressed:compressed size per file
    MAX_ZIP_ENTRIES = 10000  # Max number of files in archive (prevent billion-file attack)

    def _strip_office(
        self,
        data: bytes,
        file_type: FileType,
    ) -> Tuple[bytes, List[MetadataField]]:
        """
        Strip metadata from Office documents (DOCX, XLSX, PPTX).

        Office Open XML files are ZIP archives containing:
        - docProps/core.xml: Author, title, subject, etc.
        - docProps/app.xml: Application info, company, manager
        - docProps/custom.xml: Custom properties
        - [Content_Types].xml: Content type definitions (keep)
        - word/comments.xml, xl/comments*.xml: Comments (remove)

        We also strip:
        - Revision history
        - Track changes author info
        - Comments

        SECURITY: Includes zip bomb protection to prevent DoS attacks.
        """
        fields = []

        try:
            # RESOURCE CLEANUP: Use context managers to ensure ZipFile objects are closed
            with zipfile.ZipFile(io.BytesIO(data)) as input_zip:
                # SECURITY: Check number of entries to prevent billion-file attack
                entry_count = len(input_zip.namelist())
                if entry_count > self.MAX_ZIP_ENTRIES:
                    logger.warning(
                        f"Office document has too many entries ({entry_count}), "
                        f"max allowed is {self.MAX_ZIP_ENTRIES}"
                    )
                    return data, [MetadataField("Office", "Error:TooManyEntries", False)]

                output_buffer = io.BytesIO()
                with zipfile.ZipFile(output_buffer, 'w', zipfile.ZIP_DEFLATED) as output_zip:
                    # Files to completely remove
                    files_to_remove = {
                        'docProps/custom.xml',  # Custom properties
                    }

                    # Files to strip content from
                    files_to_clean = {
                        'docProps/core.xml',
                        'docProps/app.xml',
                    }

                    # Patterns for files to remove
                    remove_patterns = ['comments', 'revisions', 'people.xml']

                    # SECURITY: Track total decompressed size for zip bomb detection
                    total_decompressed = 0

                    for item in input_zip.namelist():
                        # Check if file should be completely removed
                        if item in files_to_remove:
                            fields.append(MetadataField("Office", f"Removed:{item}", True))
                            continue

                        # Check patterns
                        item_lower = item.lower()
                        if any(p in item_lower for p in remove_patterns):
                            fields.append(MetadataField("Office", f"Removed:{item}", True))
                            continue

                        # SECURITY: Check compressed vs uncompressed size ratio per entry
                        info = input_zip.getinfo(item)
                        if info.compress_size > 0:
                            ratio = info.file_size / info.compress_size
                            if ratio > self.MAX_EXTRACTION_RATIO:
                                logger.warning(
                                    f"Zip bomb detected in {item}: ratio {ratio:.1f}x "
                                    f"exceeds max {self.MAX_EXTRACTION_RATIO}x"
                                )
                                return data, [MetadataField("Office", "Error:ZipBombDetected", False)]

                        content = input_zip.read(item)

                        # SECURITY: Track total decompressed size
                        total_decompressed += len(content)
                        if total_decompressed > self.MAX_DECOMPRESSED_SIZE:
                            logger.warning(
                                f"Office document decompressed size ({total_decompressed}) "
                                f"exceeds max {self.MAX_DECOMPRESSED_SIZE // (1024*1024)}MB"
                            )
                            return data, [MetadataField("Office", "Error:TooLarge", False)]

                        # Clean metadata files
                        if item in files_to_clean:
                            content, item_fields = self._clean_office_xml(content, item)
                            fields.extend(item_fields)

                        output_zip.writestr(item, content)

                return output_buffer.getvalue(), fields

        except Exception as e:
            logger.error(f"Office document stripping failed: {e}")
            return data, fields
    
    def _clean_office_xml(
        self,
        content: bytes,
        filename: str,
    ) -> Tuple[bytes, List[MetadataField]]:
        """
        Clean an Office XML file by removing sensitive elements.
        """
        fields = []
        
        try:
            # Parse XML
            root = ET.fromstring(content)
            
            # Find and remove all child elements
            # We want to keep the root element but clear its children
            children_to_remove = []
            
            for child in root:
                # Get tag name without namespace
                tag = child.tag
                if '}' in tag:
                    tag = tag.split('}')[1]
                
                # Record what we're removing
                is_sensitive = tag.lower() in SENSITIVE_OFFICE_FIELDS
                fields.append(MetadataField("Office", tag, is_sensitive))
                children_to_remove.append(child)
            
            # Remove children
            for child in children_to_remove:
                root.remove(child)
            
            # Serialize back
            return ET.tostring(root, encoding='unicode').encode('utf-8'), fields
            
        except Exception as e:
            logger.warning(f"Failed to clean {filename}: {e}")
            return content, fields
# HIGH-LEVEL API
class FileProtector:
    """
    High-level API for complete file protection.
    
    Combines metadata stripping with face detection/redaction.
    
    Usage:
        protector = FileProtector(models_dir)
        clean_bytes, result = protector.process(file_bytes, filename)
    """
    
    def __init__(
        self,
        models_dir: Optional[Path] = None,
        strip_metadata: bool = True,
        detect_faces: bool = True,
        face_redaction_method: str = "blur",
    ):
        """
        Initialize file protector.
        
        Args:
            models_dir: Path to models directory (required if detect_faces=True)
            strip_metadata: Whether to strip metadata
            detect_faces: Whether to detect and redact faces
            face_redaction_method: "blur", "pixelate", or "fill"
        """
        self.strip_metadata = strip_metadata
        self.detect_faces = detect_faces
        
        self._metadata_stripper = MetadataStripper() if strip_metadata else None
        
        if detect_faces:
            if models_dir is None:
                raise ValueError("models_dir required when detect_faces=True")
            
            # Import here to avoid circular dependency
            from .face_detection import FaceProtector
            self._face_protector = FaceProtector(
                models_dir=models_dir,
                method=face_redaction_method,
            )
        else:
            self._face_protector = None
    
    def process(
        self,
        data: bytes,
        filename: str = "",
    ) -> Tuple[bytes, dict]:
        """
        Process file: strip metadata and optionally detect/redact faces.
        
        Args:
            data: File bytes
            filename: Original filename
            
        Returns:
            Tuple of (processed_bytes, result_dict)
        """
        result = {
            "filename": filename,
            "original_size": len(data),
            "metadata_stripped": False,
            "faces_redacted": False,
        }
        
        # Step 1: Strip metadata FIRST (before any image processing)
        if self._metadata_stripper:
            data, meta_result = self._metadata_stripper.strip(data, filename)
            result["metadata"] = meta_result.to_audit_dict()
            result["metadata_stripped"] = True
        
        # Step 2: Face detection (only for images)
        if self._face_protector:
            file_type = detect_file_type(data)
            
            if file_type in (FileType.JPEG, FileType.PNG, FileType.TIFF, 
                            FileType.WEBP, FileType.BMP):
                try:
                    import numpy as np
                    from PIL import Image
                    
                    # Load image
                    img = Image.open(io.BytesIO(data))
                    img_array = np.array(img)
                    
                    # Process faces
                    face_result, redacted_array = self._face_protector.process(img_array)
                    
                    if face_result.redaction_applied:
                        # Save back to bytes
                        redacted_img = Image.fromarray(redacted_array)
                        output = io.BytesIO()
                        
                        # Preserve format
                        fmt = {
                            FileType.JPEG: 'JPEG',
                            FileType.PNG: 'PNG',
                            FileType.TIFF: 'TIFF',
                            FileType.WEBP: 'WEBP',
                            FileType.BMP: 'BMP',
                        }.get(file_type, 'PNG')
                        
                        if fmt == 'JPEG':
                            redacted_img.save(output, format=fmt, quality=95)
                        else:
                            redacted_img.save(output, format=fmt)
                        
                        data = output.getvalue()
                        result["faces_redacted"] = True
                    
                    result["face_detection"] = face_result.to_audit_dict()
                    
                except Exception as e:
                    logger.error(f"Face detection failed: {e}")
                    result["face_detection_error"] = str(e)
        
        result["final_size"] = len(data)
        
        return data, result
