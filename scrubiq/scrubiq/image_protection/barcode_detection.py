"""
Barcode and QR Code Detection for ScrubIQ using pyzbar.

pyzbar wraps the zbar library for barcode decoding.
License: MIT (pyzbar wrapper), LGPL (zbar library - OK for dynamic linking)

Barcodes in medical documents often encode PHI:
- PDF417 on driver's licenses (name, DOB, address, DL#)
- Patient wristband barcodes (MRN)
- Insurance card barcodes (member ID, group #)
- Prescription bottle barcodes (Rx#, patient info)
- Lab specimen labels (patient ID, MRN)
- Medical record barcodes

Requirements:
    pip install pyzbar Pillow
    Linux: sudo apt-get install libzbar0
    macOS: brew install zbar
    Windows: Included in pyzbar wheel
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Lazy import pyzbar
_pyzbar = None


def _get_pyzbar():
    """Lazy load pyzbar to avoid startup cost if not used."""
    global _pyzbar
    if _pyzbar is None:
        try:
            from pyzbar import pyzbar
            _pyzbar = pyzbar
        except ImportError as e:
            raise ImportError(
                "pyzbar not installed. Install with:\n"
                "  pip install pyzbar\n"
                "  Linux: sudo apt-get install libzbar0\n"
                "  macOS: brew install zbar"
            ) from e
    return _pyzbar


class BarcodeType(str, Enum):
    """Supported barcode types."""
    QRCODE = "QRCODE"
    PDF417 = "PDF417"
    CODE128 = "CODE128"
    CODE39 = "CODE39"
    EAN13 = "EAN13"
    EAN8 = "EAN8"
    UPCA = "UPCA"
    UPCE = "UPCE"
    I25 = "I25"  # Interleaved 2 of 5
    DATABAR = "DATABAR"
    DATABAR_EXP = "DATABAR-EXP"
    CODABAR = "CODABAR"
    UNKNOWN = "UNKNOWN"
    
    @classmethod
    def from_string(cls, s: str) -> "BarcodeType":
        """Convert string to BarcodeType, defaulting to UNKNOWN."""
        try:
            return cls(s.upper())
        except ValueError:
            return cls.UNKNOWN


@dataclass
class BarcodeDetection:
    """A detected barcode or QR code."""
    x: int
    y: int
    width: int
    height: int
    barcode_type: BarcodeType
    confidence: float = 1.0  # pyzbar doesn't provide confidence, assume 1.0 if decoded
    data_hash: str = ""  # SHA256 hash of decoded data (for audit without storing PHI)
    data_length: int = 0  # Length of decoded data
    polygon: List[Tuple[int, int]] = field(default_factory=list)  # Actual barcode polygon
    
    # Note: We intentionally don't store the decoded data itself
    # as it may contain PHI. Only store hash for audit purposes.
    
    @property
    def x2(self) -> int:
        return self.x + self.width
    
    @property
    def y2(self) -> int:
        return self.y + self.height
    
    @property
    def area(self) -> int:
        return self.width * self.height
    
    @property
    def bbox(self) -> Tuple[int, int, int, int]:
        """Return (x1, y1, x2, y2) format."""
        return (self.x, self.y, self.x2, self.y2)
    
    def to_dict(self) -> dict:
        """Convert to dict for serialization. Excludes decoded data for PHI safety."""
        return {
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "barcode_type": self.barcode_type.value,
            "confidence": round(self.confidence, 3),
            "data_length": self.data_length,
            # data_hash intentionally excluded from default output
        }


@dataclass
class BarcodeDetectionResult:
    """Result of barcode detection on an image."""
    barcodes_detected: int
    detections: List[BarcodeDetection]
    processing_time_ms: float
    image_width: int
    image_height: int
    barcode_types_found: List[str] = field(default_factory=list)
    
    def to_audit_dict(self) -> dict:
        return {
            "barcodes_detected": self.barcodes_detected,
            "barcode_types": self.barcode_types_found,
            "processing_time_ms": round(self.processing_time_ms, 1),
            "image_size": f"{self.image_width}x{self.image_height}",
        }


class BarcodeDetector:
    """
    pyzbar-based barcode and QR code detection.
    
    Detects and decodes barcodes in document images. Unlike YOLO-based
    detection, pyzbar actually decodes the barcode content, which lets
    us validate that it contains data (vs false positives).
    
    Supported formats:
    - QR Code
    - PDF417 (driver's licenses, boarding passes)
    - Code 128, Code 39
    - EAN-13, EAN-8, UPC-A, UPC-E
    - Interleaved 2 of 5
    - DataBar
    """
    
    def __init__(self, symbols: Optional[List[str]] = None):
        """
        Initialize barcode detector.
        
        Args:
            symbols: List of barcode types to detect. None = all types.
                     Example: ["QRCODE", "PDF417", "CODE128"]
        """
        self._symbols = None
        if symbols:
            pyzbar = _get_pyzbar()
            from pyzbar.pyzbar import ZBarSymbol
            self._symbols = [getattr(ZBarSymbol, s.upper()) for s in symbols if hasattr(ZBarSymbol, s.upper())]
    
    def detect(self, image: np.ndarray) -> BarcodeDetectionResult:
        """
        Detect barcodes in an image.
        
        Args:
            image: Image as numpy array (BGR or grayscale)
            
        Returns:
            BarcodeDetectionResult with detected barcodes
        """
        start_time = time.perf_counter()
        
        if image is None or image.size == 0:
            return BarcodeDetectionResult(
                barcodes_detected=0,
                detections=[],
                processing_time_ms=0,
                image_width=0,
                image_height=0,
            )
        
        height, width = image.shape[:2]
        
        # Convert BGR to grayscale if needed (pyzbar works better with grayscale)
        if len(image.shape) == 3:
            gray = np.mean(image, axis=2).astype(np.uint8)
        else:
            # Handle 1-bit images (mode '1' from PIL): True=white(1), False=black(0)
            # Scale to 0-255 for pyzbar: True->255 (white), False->0 (black)
            if image.dtype == bool:
                gray = (image.astype(np.uint8) * 255)
            elif image.dtype != np.uint8 or image.max() <= 1:
                # Handle other cases: ensure uint8 and proper range
                gray = (image.astype(np.float32) / max(image.max(), 1) * 255).astype(np.uint8)
            else:
                gray = image
        
        pyzbar = _get_pyzbar()
        
        # Detect barcodes
        if self._symbols:
            decoded = pyzbar.decode(gray, symbols=self._symbols)
        else:
            decoded = pyzbar.decode(gray)
        
        detections = []
        barcode_types = []
        
        for barcode in decoded:
            # Get bounding box
            rect = barcode.rect
            x, y, w, h = rect.left, rect.top, rect.width, rect.height
            
            # Get polygon points
            polygon = [(p.x, p.y) for p in barcode.polygon]
            
            # Hash the decoded data for audit (don't store raw data - PHI risk)
            data_bytes = barcode.data
            data_hash = hashlib.sha256(data_bytes).hexdigest()[:16]
            
            barcode_type = BarcodeType.from_string(barcode.type)
            
            detections.append(BarcodeDetection(
                x=max(0, x),
                y=max(0, y),
                width=min(w, width - x),
                height=min(h, height - y),
                barcode_type=barcode_type,
                confidence=1.0,  # pyzbar doesn't provide confidence
                data_hash=data_hash,
                data_length=len(data_bytes),
                polygon=polygon,
            ))
            
            if barcode_type.value not in barcode_types:
                barcode_types.append(barcode_type.value)
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return BarcodeDetectionResult(
            barcodes_detected=len(detections),
            detections=detections,
            processing_time_ms=elapsed_ms,
            image_width=width,
            image_height=height,
            barcode_types_found=barcode_types,
        )
    
    def detect_from_path(self, image_path: str) -> BarcodeDetectionResult:
        """Detect barcodes from an image file path."""
        import cv2
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError(f"Could not load image: {image_path}")
        return self.detect(image)
    
    def detect_from_bytes(self, image_bytes: bytes) -> BarcodeDetectionResult:
        """Detect barcodes from image bytes."""
        import cv2
        nparr = np.frombuffer(image_bytes, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError("Could not decode image from bytes")
        return self.detect(image)
    
    def detect_from_pil(self, pil_image) -> BarcodeDetectionResult:
        """Detect barcodes from a PIL Image."""
        # Convert PIL to numpy array
        image = np.array(pil_image)
        # PIL is RGB, but our detect() handles both
        return self.detect(image)


def _pixelate_region(image: np.ndarray, x1: int, y1: int, x2: int, y2: int, block_size: int = 8) -> np.ndarray:
    """Pixelate a region of an image."""
    import cv2

    roi = image[y1:y2, x1:x2]
    if roi.size == 0:
        return image

    h, w = roi.shape[:2]
    if h < block_size or w < block_size:
        block_size = max(1, min(h, w) // 2)

    if block_size < 1:
        block_size = 1

    # Downscale then upscale to create pixelation effect
    small = cv2.resize(roi, (max(1, w // block_size), max(1, h // block_size)), interpolation=cv2.INTER_LINEAR)
    pixelated = cv2.resize(small, (w, h), interpolation=cv2.INTER_NEAREST)

    result = image.copy()
    result[y1:y2, x1:x2] = pixelated
    return result


def redact_barcodes(
    image: np.ndarray,
    detections: List[BarcodeDetection],
    method: str = "black",
    padding: float = 0.05,
    use_polygon: bool = True,
) -> np.ndarray:
    """
    Redact detected barcodes in an image.

    Args:
        image: Image as numpy array (BGR)
        detections: List of BarcodeDetection objects
        method: Redaction method - "black", "blur", or "pixelate"
        padding: Expand bounding box by this fraction (0.05 = 5%)
        use_polygon: If True, use polygon mask instead of rectangle

    Returns:
        Image with barcodes redacted
    """
    import cv2

    # Handle bool arrays (from 1-bit images like QR codes)
    if image.dtype == bool:
        image = image.astype(np.uint8) * 255

    result = image.copy()
    height, width = image.shape[:2]

    for det in detections:
        # Calculate padded bounding box (used for all methods)
        pad_w = int(det.width * padding)
        pad_h = int(det.height * padding)
        x1 = max(0, det.x - pad_w)
        y1 = max(0, det.y - pad_h)
        x2 = min(width, det.x2 + pad_w)
        y2 = min(height, det.y2 + pad_h)

        if use_polygon and det.polygon and len(det.polygon) >= 3:
            # Use polygon for more precise redaction
            pts = np.array(det.polygon, np.int32)

            if method == "black":
                cv2.fillPoly(result, [pts], (0, 0, 0))
            elif method == "blur":
                # Create mask from polygon
                mask = np.zeros((height, width), dtype=np.uint8)
                cv2.fillPoly(mask, [pts], 255)

                # Blur the entire image
                blurred = cv2.GaussianBlur(result, (51, 51), 20)

                # Apply blur only in masked region (handle grayscale vs RGB)
                if len(result.shape) == 2:
                    result = np.where(mask == 255, blurred, result)
                else:
                    result = np.where(mask[:, :, None] == 255, blurred, result)
            elif method == "pixelate":
                # Pixelate using bounding box (polygon pixelation is complex)
                # block_size=16 ensures barcode is undecodable (4 was insufficient)
                result = _pixelate_region(result, x1, y1, x2, y2, block_size=16)
        else:
            # Fall back to bounding box
            if method == "black":
                result[y1:y2, x1:x2] = 0
            elif method == "blur":
                roi = result[y1:y2, x1:x2]
                if roi.size > 0:
                    blurred = cv2.GaussianBlur(roi, (51, 51), 20)
                    result[y1:y2, x1:x2] = blurred
            elif method == "pixelate":
                # block_size=16 ensures barcode is undecodable (4 was insufficient)
                result = _pixelate_region(result, x1, y1, x2, y2, block_size=16)

    return result


# Module-level singleton for convenience
_default_detector: Optional[BarcodeDetector] = None


def get_detector() -> BarcodeDetector:
    """Get or create the default barcode detector singleton."""
    global _default_detector
    if _default_detector is None:
        _default_detector = BarcodeDetector()
    return _default_detector


def detect_barcodes(image: np.ndarray) -> BarcodeDetectionResult:
    """Convenience function to detect barcodes using default detector."""
    return get_detector().detect(image)


# High-risk barcode types for PHI
PHI_HIGH_RISK_TYPES = {
    BarcodeType.PDF417,    # Driver's licenses, ID cards
    BarcodeType.QRCODE,    # Can contain anything
    BarcodeType.CODE128,   # Common for patient wristbands
}


def is_high_risk_barcode(detection: BarcodeDetection) -> bool:
    """Check if a barcode type is high-risk for containing PHI."""
    return detection.barcode_type in PHI_HIGH_RISK_TYPES


# CLI for testing
if __name__ == "__main__":
    import sys
    import cv2
    
    if len(sys.argv) < 2:
        print("Usage: python barcode_detection.py <image_path>")
        sys.exit(1)
    
    image_path = sys.argv[1]
    detector = BarcodeDetector()
    
    result = detector.detect_from_path(image_path)
    print(f"Detected {result.barcodes_detected} barcodes in {result.processing_time_ms:.1f}ms")
    
    for i, det in enumerate(result.detections):
        risk = "HIGH RISK" if is_high_risk_barcode(det) else "low risk"
        print(f"  Barcode {i+1}: {det.barcode_type.value} at ({det.x}, {det.y}) "
              f"{det.width}x{det.height} [{risk}] data_len={det.data_length}")
    
    # Save redacted version
    if result.barcodes_detected > 0:
        image = cv2.imread(image_path)
        redacted = redact_barcodes(image, result.detections)
        output_path = image_path.rsplit(".", 1)[0] + "_redacted.jpg"
        cv2.imwrite(output_path, redacted)
        print(f"Saved redacted image to {output_path}")
