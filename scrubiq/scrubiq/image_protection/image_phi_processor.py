"""
Unified Image PHI Processor for ScrubIQ.

Orchestrates all image-based PHI detection:
- Face detection (YuNet - MIT)
- Barcode detection (pyzbar - MIT)
- Handwriting detection (YOLOX - Apache 2.0)
- Signature detection (YOLOX - Apache 2.0)

Strategy: Run ALL detectors on EVERY image.
- Models are fast (~20-50ms each on CPU)
- Cost of false negative (PHI leak) >> cost of running extra detector
- Defense in depth - multiple detection methods catch different PHI
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import cv2
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class PHIRegion:
    """A detected PHI region in an image."""
    x: int
    y: int
    width: int
    height: int
    phi_type: str  # "face", "barcode", "handwriting", "signature"
    confidence: float
    detector: str  # Which detector found this
    metadata: Dict = field(default_factory=dict)
    
    @property
    def x2(self) -> int:
        return self.x + self.width
    
    @property
    def y2(self) -> int:
        return self.y + self.height
    
    @property
    def bbox(self) -> Tuple[int, int, int, int]:
        """Return (x1, y1, x2, y2) format."""
        return (self.x, self.y, self.x2, self.y2)
    
    @property
    def area(self) -> int:
        return self.width * self.height


@dataclass
class ImagePHIResult:
    """Complete PHI analysis result for an image."""
    phi_regions: List[PHIRegion]
    total_phi_detected: int
    faces_detected: int
    barcodes_detected: int
    handwriting_detected: int
    signatures_detected: int
    processing_time_ms: float
    image_width: int
    image_height: int
    detectors_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    @property
    def has_phi(self) -> bool:
        return self.total_phi_detected > 0
    
    def to_audit_dict(self) -> dict:
        return {
            "total_phi_detected": self.total_phi_detected,
            "faces": self.faces_detected,
            "barcodes": self.barcodes_detected,
            "handwriting": self.handwriting_detected,
            "signatures": self.signatures_detected,
            "processing_time_ms": round(self.processing_time_ms, 1),
            "image_size": f"{self.image_width}x{self.image_height}",
            "detectors_run": self.detectors_run,
            "errors": self.errors if self.errors else None,
        }


class ImagePHIProcessor:
    """
    Unified processor for detecting PHI in images.
    
    Runs all enabled detectors and aggregates results.
    """
    
    def __init__(
        self,
        enable_face: bool = True,
        enable_barcode: bool = True,
        enable_handwriting: bool = True,
        enable_signature: bool = True,
        models_dir: Optional[Path] = None,
        face_confidence: float = 0.7,
        yolo_confidence: float = 0.5,
    ):
        """
        Initialize the image PHI processor.
        
        Args:
            enable_face: Enable face detection
            enable_barcode: Enable barcode detection
            enable_handwriting: Enable handwriting detection
            enable_signature: Enable signature detection
            models_dir: Directory containing model files
            face_confidence: Minimum confidence for face detection
            yolo_confidence: Minimum confidence for YOLO-based detection
        """
        self.enable_face = enable_face
        self.enable_barcode = enable_barcode
        self.enable_handwriting = enable_handwriting
        self.enable_signature = enable_signature
        self.models_dir = Path(models_dir) if models_dir else None
        self.face_confidence = face_confidence
        self.yolo_confidence = yolo_confidence
        
        # Lazy-loaded detectors
        self._face_detector = None
        self._barcode_detector = None
        self._handwriting_detector = None
        self._signature_detector = None
    
    @property
    def face_detector(self):
        """Lazy load face detector."""
        if self._face_detector is None and self.enable_face:
            from .face_detection import FaceDetector
            model_path = None
            if self.models_dir:
                model_path = self.models_dir / "face_detection_yunet_2023mar.onnx"
            self._face_detector = FaceDetector(
                model_path=model_path,
                score_threshold=self.face_confidence,
            )
        return self._face_detector
    
    @property
    def barcode_detector(self):
        """Lazy load barcode detector."""
        if self._barcode_detector is None and self.enable_barcode:
            from .barcode_detection import BarcodeDetector
            self._barcode_detector = BarcodeDetector()
        return self._barcode_detector
    
    @property
    def handwriting_detector(self):
        """Lazy load handwriting detector."""
        if self._handwriting_detector is None and self.enable_handwriting:
            from .handwriting_detection import HandwritingDetector
            models_dir = self.models_dir
            if models_dir is None:
                models_dir = Path(__file__).parent.parent.parent / ".scrubiq" / "models"
            if (models_dir / "yolov8n_handwriting_detection.onnx").exists():
                self._handwriting_detector = HandwritingDetector(
                    models_dir=models_dir,
                    confidence_threshold=self.yolo_confidence,
                )
        return self._handwriting_detector
    
    @property
    def signature_detector(self):
        """Lazy load signature detector."""
        if self._signature_detector is None and self.enable_signature:
            from .signature_detection import SignatureDetector
            # SignatureDetector uses pure OpenCV - no model file needed
            self._signature_detector = SignatureDetector(
                confidence_threshold=self.yolo_confidence,
            )
        return self._signature_detector
    
    def process(self, image: np.ndarray) -> ImagePHIResult:
        """
        Process an image for PHI detection.
        
        Args:
            image: BGR image as numpy array
            
        Returns:
            ImagePHIResult with all detected PHI regions
        """
        start_time = time.perf_counter()
        
        if image is None or image.size == 0:
            return ImagePHIResult(
                phi_regions=[],
                total_phi_detected=0,
                faces_detected=0,
                barcodes_detected=0,
                handwriting_detected=0,
                signatures_detected=0,
                processing_time_ms=0,
                image_width=0,
                image_height=0,
            )
        
        height, width = image.shape[:2]
        phi_regions = []
        detectors_run = []
        errors = []
        
        faces_detected = 0
        barcodes_detected = 0
        handwriting_detected = 0
        signatures_detected = 0
        
        # Face detection
        if self.enable_face:
            try:
                if self.face_detector:
                    result = self.face_detector.detect(image)
                    detectors_run.append("face_yunet")
                    faces_detected = result.faces_detected
                    
                    for det in result.detections:
                        phi_regions.append(PHIRegion(
                            x=det.x,
                            y=det.y,
                            width=det.width,
                            height=det.height,
                            phi_type="face",
                            confidence=det.confidence,
                            detector="yunet",
                            metadata={"has_landmarks": det.landmarks is not None},
                        ))
            except Exception as e:
                logger.error(f"Face detection failed: {e}")
                errors.append(f"face: {str(e)}")
        
        # Barcode detection
        if self.enable_barcode:
            try:
                if self.barcode_detector:
                    result = self.barcode_detector.detect(image)
                    detectors_run.append("barcode_pyzbar")
                    barcodes_detected = result.barcodes_detected
                    
                    for det in result.detections:
                        phi_regions.append(PHIRegion(
                            x=det.x,
                            y=det.y,
                            width=det.width,
                            height=det.height,
                            phi_type="barcode",
                            confidence=det.confidence,
                            detector="pyzbar",
                            metadata={
                                "barcode_type": det.barcode_type.value,
                                "data_length": det.data_length,
                            },
                        ))
            except Exception as e:
                logger.error(f"Barcode detection failed: {e}")
                errors.append(f"barcode: {str(e)}")
        
        # Convert to RGB once for detectors that need it (handwriting, signature)
        # This avoids duplicate color conversion when both are enabled
        rgb_image = None
        needs_rgb = (
            (self.enable_handwriting and self.handwriting_detector) or
            (self.enable_signature and self.signature_detector)
        )
        if needs_rgb:
            rgb_image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

        # Handwriting detection
        if self.enable_handwriting and self.handwriting_detector:
            try:
                detections = self.handwriting_detector.detect(rgb_image)
                detectors_run.append("handwriting_yolox")
                handwriting_detected = len(detections)

                for det in detections:
                    phi_regions.append(PHIRegion(
                        x=det.x,
                        y=det.y,
                        width=det.width,
                        height=det.height,
                        phi_type="handwriting",
                        confidence=det.confidence,
                        detector="yolox",
                        metadata={"class": det.class_name},
                    ))
            except Exception as e:
                logger.error(f"Handwriting detection failed: {e}")
                errors.append(f"handwriting: {str(e)}")

        # Signature detection
        if self.enable_signature and self.signature_detector:
            try:
                detections = self.signature_detector.detect(rgb_image)
                detectors_run.append("signature_opencv")
                signatures_detected = len(detections)

                for det in detections:
                    phi_regions.append(PHIRegion(
                        x=det.x,
                        y=det.y,
                        width=det.width,
                        height=det.height,
                        phi_type="signature",
                        confidence=det.confidence,
                        detector="opencv",
                        metadata={"class": det.class_name},
                    ))
            except Exception as e:
                logger.error(f"Signature detection failed: {e}")
                errors.append(f"signature: {str(e)}")
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return ImagePHIResult(
            phi_regions=phi_regions,
            total_phi_detected=len(phi_regions),
            faces_detected=faces_detected,
            barcodes_detected=barcodes_detected,
            handwriting_detected=handwriting_detected,
            signatures_detected=signatures_detected,
            processing_time_ms=elapsed_ms,
            image_width=width,
            image_height=height,
            detectors_run=detectors_run,
            errors=errors,
        )
    
    def process_from_path(self, image_path: str) -> ImagePHIResult:
        """Process an image file for PHI detection."""
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError(f"Could not load image: {image_path}")
        return self.process(image)
    
    def process_from_bytes(self, image_bytes: bytes) -> ImagePHIResult:
        """Process image bytes for PHI detection."""
        nparr = np.frombuffer(image_bytes, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError("Could not decode image from bytes")
        return self.process(image)


def redact_phi_regions(
    image: np.ndarray,
    regions: List[PHIRegion],
    method: str = "black",
    padding: float = 0.1,
) -> np.ndarray:
    """
    Redact PHI regions in an image.
    
    Args:
        image: BGR image as numpy array
        regions: List of PHIRegion objects to redact
        method: Redaction method - "black", "blur", or "pixelate"
        padding: Expand bounding box by this fraction
        
    Returns:
        Image with PHI regions redacted
    """
    result = image.copy()
    height, width = image.shape[:2]
    
    for region in regions:
        # Apply padding
        pad_w = int(region.width * padding)
        pad_h = int(region.height * padding)
        
        x1 = max(0, region.x - pad_w)
        y1 = max(0, region.y - pad_h)
        x2 = min(width, region.x2 + pad_w)
        y2 = min(height, region.y2 + pad_h)
        
        if method == "black":
            result[y1:y2, x1:x2] = 0
        elif method == "blur":
            roi = result[y1:y2, x1:x2]
            if roi.size > 0:
                blurred = cv2.GaussianBlur(roi, (99, 99), 30)
                result[y1:y2, x1:x2] = blurred
        elif method == "pixelate":
            roi = result[y1:y2, x1:x2]
            if roi.size > 0:
                h, w = roi.shape[:2]
                small = cv2.resize(roi, (max(1, w // 10), max(1, h // 10)), interpolation=cv2.INTER_LINEAR)
                pixelated = cv2.resize(small, (w, h), interpolation=cv2.INTER_NEAREST)
                result[y1:y2, x1:x2] = pixelated
    
    return result


def draw_phi_regions(
    image: np.ndarray,
    regions: List[PHIRegion],
    show_labels: bool = True,
) -> np.ndarray:
    """
    Draw PHI region bounding boxes on an image (for debugging/visualization).
    
    Args:
        image: BGR image as numpy array
        regions: List of PHIRegion objects
        show_labels: Whether to draw labels
        
    Returns:
        Image with bounding boxes drawn
    """
    result = image.copy()
    
    # Colors for different PHI types
    colors = {
        "face": (0, 0, 255),       # Red
        "barcode": (0, 255, 0),    # Green
        "handwriting": (255, 0, 0), # Blue
        "signature": (255, 165, 0), # Orange
    }
    
    for region in regions:
        color = colors.get(region.phi_type, (128, 128, 128))
        
        # Draw rectangle
        cv2.rectangle(result, (region.x, region.y), (region.x2, region.y2), color, 2)
        
        if show_labels:
            label = f"{region.phi_type} ({region.confidence:.2f})"
            cv2.putText(
                result, label, (region.x, region.y - 5),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1
            )
    
    return result


# Module-level singleton
_default_processor: Optional[ImagePHIProcessor] = None


def get_processor() -> ImagePHIProcessor:
    """Get or create the default image PHI processor."""
    global _default_processor
    if _default_processor is None:
        _default_processor = ImagePHIProcessor()
    return _default_processor


def process_image(image: np.ndarray) -> ImagePHIResult:
    """Convenience function to process image using default processor."""
    return get_processor().process(image)


# CLI for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python image_phi_processor.py <image_path> [--redact] [--draw]")
        sys.exit(1)
    
    image_path = sys.argv[1]
    do_redact = "--redact" in sys.argv
    do_draw = "--draw" in sys.argv
    
    processor = ImagePHIProcessor()
    result = processor.process_from_path(image_path)
    
    print(f"\n=== PHI Detection Results ===")
    print(f"Processing time: {result.processing_time_ms:.1f}ms")
    print(f"Total PHI regions: {result.total_phi_detected}")
    print(f"  Faces: {result.faces_detected}")
    print(f"  Barcodes: {result.barcodes_detected}")
    print(f"  Handwriting: {result.handwriting_detected}")
    print(f"  Signatures: {result.signatures_detected}")
    print(f"Detectors run: {', '.join(result.detectors_run)}")
    
    if result.errors:
        print(f"Errors: {result.errors}")
    
    print(f"\nDetailed regions:")
    for i, region in enumerate(result.phi_regions):
        print(f"  {i+1}. {region.phi_type} at ({region.x}, {region.y}) "
              f"{region.width}x{region.height} conf={region.confidence:.2f}")
    
    # Save outputs
    image = cv2.imread(image_path)
    base_path = image_path.rsplit(".", 1)[0]
    
    if do_draw:
        drawn = draw_phi_regions(image, result.phi_regions)
        output_path = f"{base_path}_phi_detected.jpg"
        cv2.imwrite(output_path, drawn)
        print(f"\nSaved detection visualization to {output_path}")
    
    if do_redact:
        redacted = redact_phi_regions(image, result.phi_regions)
        output_path = f"{base_path}_redacted.jpg"
        cv2.imwrite(output_path, redacted)
        print(f"Saved redacted image to {output_path}")
