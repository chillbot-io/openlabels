"""
Image embedded label writer.

Supports JPEG, PNG, TIFF, WebP.
Prefers XMP metadata, falls back to EXIF UserComment for JPEG.
"""

from pathlib import Path
from typing import Optional

from ...core.labels import LabelSet
from .base import EmbeddedLabelWriter, logger


class ImageLabelWriter(EmbeddedLabelWriter):
    """
    Write/read labels to image XMP/EXIF metadata.

    Supports JPEG, PNG, TIFF, WebP.
    Prefers XMP metadata, falls back to EXIF UserComment for JPEG.
    """

    SUPPORTED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp'}

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def write(self, path: Path, label_set: LabelSet) -> bool:
        """Write LabelSet to image metadata."""
        try:
            # Try using piexif for JPEG EXIF
            if path.suffix.lower() in {'.jpg', '.jpeg'}:
                return self._write_jpeg_exif(path, label_set)

            # For other formats, try PIL with custom metadata
            return self._write_pil_metadata(path, label_set)

        except (OSError, ValueError) as e:
            logger.error(f"Failed to write image labels: {e}")
            return False

    def read(self, path: Path) -> Optional[LabelSet]:
        """Read LabelSet from image metadata."""
        try:
            if path.suffix.lower() in {'.jpg', '.jpeg'}:
                result = self._read_jpeg_exif(path)
                if result:
                    return result

            return self._read_pil_metadata(path)

        except (OSError, ValueError) as e:
            logger.debug(f"No labels found in image: {e}")
            return None

    def _write_jpeg_exif(self, path: Path, label_set: LabelSet) -> bool:
        """Write to JPEG EXIF UserComment."""
        try:
            import piexif
        except ImportError:
            logger.warning("piexif not installed, trying PIL fallback")
            return self._write_pil_metadata(path, label_set)

        try:
            exif_dict = piexif.load(str(path))
        except (OSError, ValueError) as e:
            logger.debug(f"Could not load existing EXIF from {path}, creating new: {e}")
            exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}}

        # Store in UserComment (tag 37510)
        json_data = label_set.to_json(compact=True)
        # UserComment requires specific encoding
        user_comment = b'ASCII\x00\x00\x00' + json_data.encode('utf-8')
        exif_dict['Exif'][piexif.ExifIFD.UserComment] = user_comment

        exif_bytes = piexif.dump(exif_dict)
        piexif.insert(exif_bytes, str(path))
        return True

    def _read_jpeg_exif(self, path: Path) -> Optional[LabelSet]:
        """Read from JPEG EXIF UserComment."""
        try:
            import piexif
        except ImportError:
            return None

        try:
            exif_dict = piexif.load(str(path))
            user_comment = exif_dict.get('Exif', {}).get(piexif.ExifIFD.UserComment)
            if user_comment:
                # Strip encoding prefix (first 8 bytes)
                if user_comment.startswith(b'ASCII\x00\x00\x00'):
                    json_str = user_comment[8:].decode('utf-8')
                    if json_str.startswith('{"v":'):
                        return LabelSet.from_json(json_str)
        except (OSError, ValueError, KeyError) as e:
            logger.debug(f"Could not read EXIF label from {path}: {e}")
        return None

    def _write_pil_metadata(self, path: Path, label_set: LabelSet) -> bool:
        """Write using PIL with PNG text chunks."""
        try:
            from PIL import Image
            from PIL.PngImagePlugin import PngInfo
        except ImportError:
            logger.warning("PIL not installed, cannot write image labels")
            return False

        img = Image.open(path)  # MED-006: closed in finally
        try:
            suffix = path.suffix.lower()

            if suffix == '.png':
                # PNG supports text metadata natively
                metadata = PngInfo()
                metadata.add_text("openlabels", label_set.to_json(compact=True))

                # Preserve existing metadata
                if hasattr(img, 'info'):
                    for key, value in img.info.items():
                        if key != 'openlabels' and isinstance(value, str):
                            metadata.add_text(key, value)

                img.save(path, pnginfo=metadata)
                return True

            # For other formats, PIL doesn't have great metadata support
            logger.warning(f"Limited metadata support for {suffix}, label may not persist")
            return False
        finally:
            img.close()

    def _read_pil_metadata(self, path: Path) -> Optional[LabelSet]:
        """Read using PIL text chunks."""
        try:
            from PIL import Image
        except ImportError:
            return None

        try:
            img = Image.open(path)  # MED-006: closed in finally
            try:
                if hasattr(img, 'info') and 'openlabels' in img.info:
                    json_str = img.info['openlabels']
                    if json_str.startswith('{"v":'):
                        return LabelSet.from_json(json_str)
            finally:
                img.close()
        except (OSError, ValueError, KeyError) as e:
            logger.debug(f"Could not read PIL label from {path}: {e}")
        return None


__all__ = ['ImageLabelWriter']
