"""
Face Detection for ScrubIQ using YuNet.

YuNet is a lightweight, fast face detector built into OpenCV.
License: MIT (via OpenCV Zoo)

Faces in medical documents are PHI and must be redacted:
- Patient photos on intake forms
- ID card photos (driver's license, insurance cards)
- Medical record photos
- Visitor badge photos

Model: face_detection_yunet_2023mar.onnx (345KB)
Download: https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx
"""

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import cv2
import numpy as np

from ..constants import OCR_READY_TIMEOUT

logger = logging.getLogger(__name__)

# Default model path - .scrubiq/models/ at project root
DEFAULT_MODEL_PATH = Path(__file__).parent.parent.parent / ".scrubiq" / "models" / "face_detection_yunet_2023mar.onnx"


@dataclass
class FaceDetection:
    """A detected face region."""
    x: int
    y: int
    width: int
    height: int
    confidence: float
    landmarks: Optional[List[Tuple[int, int]]] = None  # 5 facial landmarks if available
    
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
        return {
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "confidence": round(self.confidence, 3),
            "has_landmarks": self.landmarks is not None,
        }


@dataclass
class FaceDetectionResult:
    """Result of face detection on an image."""
    faces_detected: int
    detections: List[FaceDetection]
    processing_time_ms: float
    image_width: int
    image_height: int
    
    def to_audit_dict(self) -> dict:
        return {
            "faces_detected": self.faces_detected,
            "processing_time_ms": round(self.processing_time_ms, 1),
            "image_size": f"{self.image_width}x{self.image_height}",
        }


class FaceDetector:
    """
    YuNet-based face detection.
    
    YuNet achieves:
    - 83.4% AP on WIDER Face Easy
    - 82.4% AP on WIDER Face Medium  
    - 70.8% AP on WIDER Face Hard
    
    Detection range: ~10x10 to 300x300 pixel faces
    Speed: ~3ms per image on CPU
    """
    
    def __init__(
        self,
        model_path: Optional[Path] = None,
        score_threshold: float = 0.7,
        nms_threshold: float = 0.3,
        top_k: int = 5000,
    ):
        """
        Initialize face detector.
        
        Args:
            model_path: Path to yunet ONNX model. Uses default if None.
            score_threshold: Minimum confidence score (0-1). Default 0.7.
            nms_threshold: NMS IoU threshold. Default 0.3.
            top_k: Max detections before NMS. Default 5000.
        """
        self.model_path = Path(model_path).expanduser() if model_path else DEFAULT_MODEL_PATH
        self.score_threshold = score_threshold
        self.nms_threshold = nms_threshold
        self.top_k = top_k
        self._detector = None
        self._current_input_size = None
        
    def _ensure_loaded(self, width: int, height: int) -> None:
        """Lazy load detector and update input size if needed."""
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"YuNet model not found at {self.model_path}. "
                f"Download from: https://github.com/opencv/opencv_zoo/raw/main/models/"
                f"face_detection_yunet/face_detection_yunet_2023mar.onnx"
            )
        
        input_size = (width, height)
        
        if self._detector is None:
            logger.info(f"Loading YuNet face detector from {self.model_path}")
            self._detector = cv2.FaceDetectorYN.create(
                str(self.model_path),
                "",
                input_size,
                self.score_threshold,
                self.nms_threshold,
                self.top_k,
            )
            self._current_input_size = input_size
            logger.info("YuNet face detector loaded")
            
        elif self._current_input_size != input_size:
            self._detector.setInputSize(input_size)
            self._current_input_size = input_size
    
    def detect(self, image: np.ndarray) -> FaceDetectionResult:
        """
        Detect faces in an image.
        
        Args:
            image: BGR image as numpy array (OpenCV format)
            
        Returns:
            FaceDetectionResult with detected faces
        """
        start_time = time.perf_counter()
        
        if image is None or image.size == 0:
            return FaceDetectionResult(
                faces_detected=0,
                detections=[],
                processing_time_ms=0,
                image_width=0,
                image_height=0,
            )

        # Convert grayscale to BGR if needed (YuNet requires 3-channel input)
        if len(image.shape) == 2:
            image = cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)
        elif len(image.shape) == 3 and image.shape[2] == 1:
            image = cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)

        height, width = image.shape[:2]

        # Minimum size check - YuNet produces garbage (infinity) for tiny images
        # A detectable face needs at least ~20x20 pixels
        MIN_DIMENSION = 20
        if width < MIN_DIMENSION or height < MIN_DIMENSION:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return FaceDetectionResult(
                faces_detected=0,
                detections=[],
                processing_time_ms=elapsed_ms,
                image_width=width,
                image_height=height,
            )

        self._ensure_loaded(width, height)

        # Detect faces
        _, faces = self._detector.detect(image)
        
        detections = []
        if faces is not None:
            for face in faces:
                # YuNet output format:
                # [x, y, w, h, x_re, y_re, x_le, y_le, x_nt, y_nt, x_rcm, y_rcm, x_lcm, y_lcm, score]
                # re=right eye, le=left eye, nt=nose tip, rcm=right corner mouth, lcm=left corner mouth

                # Skip faces with invalid (infinity/NaN) values - can happen with tiny images
                if not all(np.isfinite(face[:14])):
                    continue

                x, y, w, h = int(face[0]), int(face[1]), int(face[2]), int(face[3])
                confidence = float(face[14])
                
                # Extract landmarks (5 points)
                landmarks = [
                    (int(face[4]), int(face[5])),    # Right eye
                    (int(face[6]), int(face[7])),    # Left eye
                    (int(face[8]), int(face[9])),    # Nose tip
                    (int(face[10]), int(face[11])),  # Right mouth corner
                    (int(face[12]), int(face[13])),  # Left mouth corner
                ]
                
                detections.append(FaceDetection(
                    x=max(0, x),
                    y=max(0, y),
                    width=min(w, width - x),
                    height=min(h, height - y),
                    confidence=confidence,
                    landmarks=landmarks,
                ))
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return FaceDetectionResult(
            faces_detected=len(detections),
            detections=detections,
            processing_time_ms=elapsed_ms,
            image_width=width,
            image_height=height,
        )
    
    def detect_from_path(self, image_path: str) -> FaceDetectionResult:
        """Detect faces from an image file path."""
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError(f"Could not load image: {image_path}")
        return self.detect(image)
    
    def detect_from_bytes(self, image_bytes: bytes) -> FaceDetectionResult:
        """Detect faces from image bytes."""
        nparr = np.frombuffer(image_bytes, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError("Could not decode image from bytes")
        return self.detect(image)


def redact_faces(
    image: np.ndarray,
    detections: List[FaceDetection],
    method: str = "black",
    padding: float = 0.1,
) -> np.ndarray:
    """
    Redact detected faces in an image.
    
    Args:
        image: BGR image as numpy array
        detections: List of FaceDetection objects
        method: Redaction method - "black", "blur", or "pixelate"
        padding: Expand bounding box by this fraction (0.1 = 10%)
        
    Returns:
        Image with faces redacted
    """
    result = image.copy()
    height, width = image.shape[:2]
    
    for det in detections:
        # Apply padding
        pad_w = int(det.width * padding)
        pad_h = int(det.height * padding)
        
        x1 = max(0, det.x - pad_w)
        y1 = max(0, det.y - pad_h)
        x2 = min(width, det.x2 + pad_w)
        y2 = min(height, det.y2 + pad_h)
        
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
                # Downscale then upscale
                small = cv2.resize(roi, (max(1, w // 10), max(1, h // 10)), interpolation=cv2.INTER_LINEAR)
                pixelated = cv2.resize(small, (w, h), interpolation=cv2.INTER_NEAREST)
                result[y1:y2, x1:x2] = pixelated
    
    return result


# --- REDACTION METHOD ENUM ---
from enum import Enum

class RedactionMethod(Enum):
    """Method for redacting detected faces."""
    BLACK = "black"       # Solid black box
    BLUR = "blur"         # Gaussian blur
    PIXELATE = "pixelate" # Pixelated/mosaic effect


# --- FACE REDACTION RESULT ---
@dataclass
class FaceRedactionResult:
    """Result of face redaction operation."""
    faces_detected: int
    faces_redacted: int
    detections: List[FaceDetection]
    processing_time_ms: float
    redaction_method: str
    image_width: int
    image_height: int
    
    @property
    def redaction_applied(self) -> bool:
        """True if any faces were redacted."""
        return self.faces_redacted > 0
    
    def to_audit_dict(self) -> dict:
        return {
            "faces_detected": self.faces_detected,
            "faces_redacted": self.faces_redacted,
            "redaction_method": self.redaction_method,
            "processing_time_ms": round(self.processing_time_ms, 1),
            "image_size": f"{self.image_width}x{self.image_height}",
        }


# --- FACE REDACTOR ---
class FaceRedactor:
    """
    Redacts faces in images using various methods.
    
    Wraps FaceDetector with redaction capabilities.
    """
    
    def __init__(
        self,
        detector: Optional[FaceDetector] = None,
        method: RedactionMethod = RedactionMethod.BLUR,
        padding: float = 0.1,
    ):
        """
        Initialize face redactor.
        
        Args:
            detector: FaceDetector instance. Creates default if None.
            method: Redaction method (blur, black, pixelate)
            padding: Expand face bbox by this fraction (0.1 = 10%)
        """
        self.detector = detector or FaceDetector()
        self.method = method
        self.padding = padding
    
    def redact(self, image: np.ndarray) -> Tuple[FaceRedactionResult, np.ndarray]:
        """
        Detect and redact faces in an image.
        
        Args:
            image: BGR image as numpy array
            
        Returns:
            Tuple of (FaceRedactionResult, redacted_image)
        """
        import time
        start = time.perf_counter()
        
        # Detect faces
        detection_result = self.detector.detect(image)
        
        # Redact
        if detection_result.faces_detected > 0:
            redacted = redact_faces(
                image, 
                detection_result.detections,
                method=self.method.value,
                padding=self.padding,
            )
        else:
            redacted = image.copy()
        
        elapsed = (time.perf_counter() - start) * 1000
        
        result = FaceRedactionResult(
            faces_detected=detection_result.faces_detected,
            faces_redacted=detection_result.faces_detected,
            detections=detection_result.detections,
            processing_time_ms=elapsed,
            redaction_method=self.method.value,
            image_width=detection_result.image_width,
            image_height=detection_result.image_height,
        )
        
        return result, redacted


# --- FACE PROTECTOR (High-level API for processor.py) ---
import threading

class FaceProtector:
    """
    High-level face protection API for the file processor.
    
    Provides:
    - Lazy model loading
    - Background initialization
    - Ready state checking
    - Warm-up capability
    """
    
    def __init__(
        self,
        models_dir: Optional[Path] = None,
        method: str = "blur",
        padding: float = 0.1,
        score_threshold: float = 0.7,
    ):
        """
        Initialize face protector.
        
        Args:
            models_dir: Directory containing face detection models
            method: Redaction method ("blur", "black", "pixelate")
            padding: Face bbox padding fraction
            score_threshold: Minimum detection confidence
        """
        self.models_dir = models_dir
        self.method = RedactionMethod(method)
        self.padding = padding
        self.score_threshold = score_threshold
        
        self._detector: Optional[FaceDetector] = None
        self._redactor: Optional[FaceRedactor] = None
        self._initialized = False
        self._loading = False
        self._ready_event = threading.Event()
        self._load_error: Optional[Exception] = None
        self._lock = threading.Lock()
    
    @property
    def is_available(self) -> bool:
        """Check if face detection model is available."""
        if self.models_dir:
            model_path = self.models_dir / "face_detection_yunet_2023mar.onnx"
            return model_path.exists()
        return DEFAULT_MODEL_PATH.exists()
    
    @property
    def is_initialized(self) -> bool:
        """Check if detector is loaded and ready."""
        return self._initialized
    
    @property
    def is_loading(self) -> bool:
        """Check if currently loading."""
        return self._loading and not self._initialized
    
    @property
    def detector(self) -> Optional[FaceDetector]:
        """Get the underlying detector."""
        return self._detector
    
    def start_loading(self) -> None:
        """Start loading models in background thread."""
        with self._lock:
            if self._initialized or self._loading:
                return
            self._loading = True
        
        thread = threading.Thread(target=self._background_load, daemon=True)
        thread.start()
    
    def _background_load(self) -> None:
        """Background model loading."""
        try:
            self._ensure_initialized()
            self.warm_up()
        except Exception as e:
            self._load_error = e
            logger.error(f"Face protector loading failed: {e}")
        finally:
            self._ready_event.set()
    
    def await_ready(self, timeout: float = OCR_READY_TIMEOUT) -> bool:
        """
        Wait for models to be ready.
        
        Args:
            timeout: Max seconds to wait
            
        Returns:
            True if ready, False if timeout
        """
        if self._initialized:
            return True
        
        if not self._loading:
            self.start_loading()
        
        ready = self._ready_event.wait(timeout=timeout)
        
        if self._load_error:
            raise self._load_error
        
        return ready
    
    def _ensure_initialized(self) -> None:
        """Lazy initialize detector and redactor."""
        if self._initialized:
            return
        
        model_path = None
        if self.models_dir:
            model_path = self.models_dir / "face_detection_yunet_2023mar.onnx"
        
        self._detector = FaceDetector(
            model_path=model_path,
            score_threshold=self.score_threshold,
        )
        
        self._redactor = FaceRedactor(
            detector=self._detector,
            method=self.method,
            padding=self.padding,
        )
        
        self._initialized = True
        logger.info("Face protector initialized")
    
    def warm_up(self) -> bool:
        """
        Pre-warm the detector with a dummy image.
        
        Returns:
            True if successful
        """
        try:
            self._ensure_initialized()
            
            # Run on tiny dummy image
            dummy = np.zeros((100, 100, 3), dtype=np.uint8)
            _ = self._detector.detect(dummy)
            
            logger.info("Face protector warm-up complete")
            return True
        except Exception as e:
            logger.warning(f"Face protector warm-up failed: {e}")
            return False
    
    def process(self, image: np.ndarray, input_rgb: bool = True) -> Tuple[FaceRedactionResult, np.ndarray]:
        """
        Process an image: detect and redact faces.
        
        Args:
            image: Image as numpy array (RGB from PIL or BGR from OpenCV)
            input_rgb: If True, image is RGB (PIL). If False, image is BGR (OpenCV).
            
        Returns:
            Tuple of (FaceRedactionResult, redacted_image) in same color format as input
        """
        self._ensure_initialized()
        
        # Convert RGB to BGR for OpenCV/YuNet
        if input_rgb:
            bgr_image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
        else:
            bgr_image = image
        
        result, redacted_bgr = self._redactor.redact(bgr_image)
        
        # Convert back to RGB if input was RGB
        if input_rgb:
            redacted = cv2.cvtColor(redacted_bgr, cv2.COLOR_BGR2RGB)
        else:
            redacted = redacted_bgr
        
        return result, redacted
    
    def process_from_bytes(self, image_bytes: bytes) -> Tuple[FaceRedactionResult, np.ndarray]:
        """Process image from bytes."""
        nparr = np.frombuffer(image_bytes, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError("Could not decode image from bytes")
        return self.process(image)


# Module-level singleton for convenience
_default_detector: Optional[FaceDetector] = None


def get_detector() -> FaceDetector:
    """Get or create the default face detector singleton."""
    global _default_detector
    if _default_detector is None:
        _default_detector = FaceDetector()
    return _default_detector


def detect_faces(image: np.ndarray) -> FaceDetectionResult:
    """Convenience function to detect faces using default detector."""
    return get_detector().detect(image)


# CLI for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python face_detection.py <image_path>")
        sys.exit(1)
    
    image_path = sys.argv[1]
    detector = FaceDetector()
    
    result = detector.detect_from_path(image_path)
    print(f"Detected {result.faces_detected} faces in {result.processing_time_ms:.1f}ms")
    
    for i, det in enumerate(result.detections):
        print(f"  Face {i+1}: ({det.x}, {det.y}) {det.width}x{det.height} conf={det.confidence:.2f}")
    
    # Save redacted version
    if result.faces_detected > 0:
        image = cv2.imread(image_path)
        redacted = redact_faces(image, result.detections)
        output_path = image_path.rsplit(".", 1)[0] + "_redacted.jpg"
        cv2.imwrite(output_path, redacted)
        print(f"Saved redacted image to {output_path}")
