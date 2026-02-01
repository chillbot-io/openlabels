"""
Signature Detection for ScrubIQ.

Uses pure OpenCV contour analysis to find signatures in documents.
No ML models required - Apache 2.0 compatible.

These regions are redacted (black box) without OCR since signatures
contain PII but aren't machine-readable text.

HIPAA Safe Harbor: Handwritten signatures are biometric identifiers that
must be de-identified (45 CFR § 164.514(b)(2)(i)).

Detection Strategy:
    1. Convert to binary (ink vs background) via adaptive threshold
    2. Find connected ink regions (contours)
    3. Score each region based on signature-like properties:
       - Aspect ratio (signatures are wider than tall)
       - Ink density (signatures have gaps/whitespace)
       - Complexity (signatures have many strokes)
       - Solidity (signatures aren't solid shapes)
    4. Regions scoring above threshold are classified as signatures

Architecture:
    Image → Grayscale → Adaptive Threshold → Contours → Scoring → Detections
"""

import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from ..constants import MODEL_LOAD_TIMEOUT
from typing import List, Optional, Tuple

import cv2
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class SignatureDetection:
    """A detected signature or handwriting region."""
    x: int
    y: int
    width: int
    height: int
    confidence: float
    class_name: str  # 'signature'

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
        """Convert to dict for serialization."""
        return {
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "confidence": round(self.confidence, 3),
            "class": self.class_name,
        }


@dataclass
class SignatureRedactionResult:
    """Result of signature detection and redaction."""
    original_hash: str
    signatures_detected: int
    detections: List[SignatureDetection]
    processing_time_ms: float
    redaction_applied: bool

    def to_audit_dict(self) -> dict:
        """Convert to audit-safe dict."""
        return {
            "original_hash": self.original_hash,
            "signatures_detected": self.signatures_detected,
            "processing_time_ms": round(self.processing_time_ms, 1),
            "redaction_applied": self.redaction_applied,
        }


class SignatureDetector:
    """
    OpenCV-based signature detection using contour analysis.

    Detects handwritten signatures in document images. Signatures are
    biometric identifiers under HIPAA and must be redacted.

    No ML models required - uses traditional computer vision.
    All parameters are tunable for different document types.
    """

    # Detection parameters - all tunable
    DEFAULT_CONFIDENCE_THRESHOLD = 0.8  # Higher threshold to reduce false positives

    # Contour filtering
    MIN_CONTOUR_AREA = 500          # Minimum ink area in pixels
    MAX_CONTOUR_AREA_RATIO = 0.5    # Max ratio of image area (skip huge regions)
    MAX_BBOX_AREA_RATIO = 0.10      # Max bounding box area ratio (signatures are small, ~10% max)

    # Signature characteristics
    MIN_ASPECT_RATIO = 1.5          # Signatures are wider than tall
    MAX_ASPECT_RATIO = 15.0         # But not extremely wide (that's a line)
    MIN_INK_DENSITY = 0.05          # Min ink pixels / bounding box area
    MAX_INK_DENSITY = 0.6           # Max density (solid shapes aren't signatures)
    MIN_COMPLEXITY = 0.3            # Perimeter^2 / area ratio (higher = more curves)
    MAX_SOLIDITY = 0.8              # Signatures aren't solid shapes

    # Preprocessing
    ADAPTIVE_BLOCK_SIZE = 15        # Block size for adaptive threshold
    ADAPTIVE_C = 10                 # Constant subtracted from mean

    # Box expansion for safety margin
    BOX_EXPANSION = 0.1             # Expand boxes by 10%
    NMS_IOU_THRESHOLD = 0.45        # NMS overlap threshold

    def __init__(
        self,
        models_dir: Path = None,  # Kept for API compatibility, not used
        confidence_threshold: float = None,
        min_aspect_ratio: float = None,
        max_aspect_ratio: float = None,
        min_ink_density: float = None,
        max_ink_density: float = None,
        min_complexity: float = None,
        max_solidity: float = None,
        min_contour_area: int = None,
    ):
        """
        Initialize signature detector.

        Args:
            models_dir: Ignored (kept for API compatibility)
            confidence_threshold: Minimum score to classify as signature (0-1)
            min_aspect_ratio: Minimum width/height ratio
            max_aspect_ratio: Maximum width/height ratio
            min_ink_density: Minimum ink fill ratio
            max_ink_density: Maximum ink fill ratio
            min_complexity: Minimum perimeter^2/area ratio
            max_solidity: Maximum convex hull fill ratio
            min_contour_area: Minimum contour area in pixels
        """
        # Store models_dir for API compatibility even though not used
        self.models_dir = Path(models_dir) if models_dir else None

        # Tunable parameters
        self.confidence_threshold = confidence_threshold or self.DEFAULT_CONFIDENCE_THRESHOLD
        self.min_aspect_ratio = min_aspect_ratio or self.MIN_ASPECT_RATIO
        self.max_aspect_ratio = max_aspect_ratio or self.MAX_ASPECT_RATIO
        self.min_ink_density = min_ink_density or self.MIN_INK_DENSITY
        self.max_ink_density = max_ink_density or self.MAX_INK_DENSITY
        self.min_complexity = min_complexity or self.MIN_COMPLEXITY
        self.max_solidity = max_solidity or self.MAX_SOLIDITY
        self.min_contour_area = min_contour_area or self.MIN_CONTOUR_AREA

        # Always initialized (no model to load)
        self._initialized = True

        logger.info("OpenCV signature detector initialized (no ML model required)")

    @property
    def is_available(self) -> bool:
        """Always available - no model file needed."""
        return True

    @property
    def is_initialized(self) -> bool:
        """Always initialized - no model to load."""
        return True

    @property
    def is_loading(self) -> bool:
        """Never loading - instant initialization."""
        return False

    def start_loading(self) -> None:
        """No-op for API compatibility."""
        pass

    def await_ready(self, timeout: float = 60.0) -> bool:
        """Always ready immediately."""
        return True

    def warm_up(self) -> None:
        """No-op for API compatibility."""
        pass

    def _preprocess(self, image: np.ndarray) -> np.ndarray:
        """
        Convert image to binary (ink = white, background = black).

        Uses adaptive thresholding which handles varying lighting.
        """
        # Convert to grayscale if needed
        if len(image.shape) == 3:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        else:
            gray = image

        # Adaptive threshold - handles varying lighting
        binary = cv2.adaptiveThreshold(
            gray,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY_INV,
            self.ADAPTIVE_BLOCK_SIZE,
            self.ADAPTIVE_C
        )

        return binary

    def _find_contours(self, binary: np.ndarray) -> List[Tuple[np.ndarray, dict]]:
        """
        Find connected ink regions and compute their properties.

        Returns:
            List of (contour, properties_dict) tuples
        """
        contours, _ = cv2.findContours(
            binary,
            cv2.RETR_EXTERNAL,  # Only outer contours
            cv2.CHAIN_APPROX_SIMPLE
        )

        img_area = binary.shape[0] * binary.shape[1]
        regions = []

        for contour in contours:
            contour_area = cv2.contourArea(contour)

            # Skip tiny regions
            if contour_area < self.min_contour_area:
                continue

            # Skip huge regions (probably background)
            if contour_area > img_area * self.MAX_CONTOUR_AREA_RATIO:
                continue

            # Bounding box
            x, y, w, h = cv2.boundingRect(contour)
            bbox_area = w * h

            # Skip if bounding box is too large (signatures are small, not whole image)
            if bbox_area > img_area * self.MAX_BBOX_AREA_RATIO:
                continue

            # Compute properties
            ink_density = contour_area / bbox_area if bbox_area > 0 else 0
            aspect_ratio = w / h if h > 0 else 0
            perimeter = cv2.arcLength(contour, True)
            complexity = (perimeter ** 2) / contour_area if contour_area > 0 else 0

            # Convex hull for solidity
            hull = cv2.convexHull(contour)
            hull_area = cv2.contourArea(hull)
            solidity = contour_area / hull_area if hull_area > 0 else 0

            props = {
                'x': x, 'y': y, 'w': w, 'h': h,
                'contour_area': contour_area,
                'ink_density': ink_density,
                'aspect_ratio': aspect_ratio,
                'complexity': complexity,
                'solidity': solidity,
            }

            regions.append((contour, props))

        return regions

    def _score_region(self, props: dict) -> float:
        """
        Score a region on how signature-like it is.

        Returns:
            Score from 0.0 to 1.0
        """
        score = 0.0
        density = props['ink_density']
        solidity = props['solidity']

        # HARD REJECT: Solid filled regions (like redaction boxes) are never signatures
        # Signatures have gaps/whitespace - solid shapes are rectangles, not handwriting
        if density > self.max_ink_density or solidity >= self.max_solidity:
            return 0.0

        # Aspect ratio check (signatures are wider than tall)
        ar = props['aspect_ratio']
        if self.min_aspect_ratio <= ar <= self.max_aspect_ratio:
            score += 0.3

        # Ink density check (signatures have gaps/whitespace)
        if self.min_ink_density <= density <= self.max_ink_density:
            score += 0.25

        # Complexity check (signatures have many strokes/curves)
        if props['complexity'] >= self.min_complexity:
            score += 0.25

        # Solidity check (signatures aren't solid shapes)
        if solidity < self.max_solidity:
            score += 0.2

        return score

    def detect(
        self,
        image: np.ndarray,
        conf_threshold: float = None,
    ) -> List[SignatureDetection]:
        """
        Detect signatures in image.

        Args:
            image: Image as numpy array (H, W, C) in BGR or RGB format
            conf_threshold: Override default confidence threshold

        Returns:
            List of SignatureDetection objects
        """
        conf_threshold = conf_threshold or self.confidence_threshold

        # Handle different image formats
        if len(image.shape) == 2:
            # Grayscale - keep as is
            pass
        elif image.shape[2] == 4:
            # RGBA - drop alpha
            image = image[:, :, :3]

        orig_h, orig_w = image.shape[:2]

        # Preprocess to binary
        binary = self._preprocess(image)

        # Find contours
        regions = self._find_contours(binary)

        logger.debug(f"Found {len(regions)} candidate ink regions")

        # Score and filter regions
        detections = []
        for contour, props in regions:
            score = self._score_region(props)

            if score >= conf_threshold:
                detections.append(SignatureDetection(
                    x=props['x'],
                    y=props['y'],
                    width=props['w'],
                    height=props['h'],
                    confidence=score,
                    class_name="signature"
                ))

        logger.debug(f"Found {len(detections)} signatures above threshold {conf_threshold}")

        # Apply NMS to remove overlapping detections
        detections = self._nms(detections)

        # Expand boxes slightly for safety
        detections = [self._expand_box(d, orig_w, orig_h) for d in detections]

        logger.debug(f"After NMS and expansion: {len(detections)} detections")

        return detections

    def _nms(self, detections: List[SignatureDetection]) -> List[SignatureDetection]:
        """Non-maximum suppression to remove overlapping detections."""
        if not detections:
            return []

        # Sort by confidence descending
        detections = sorted(detections, key=lambda d: d.confidence, reverse=True)

        keep = []
        while detections:
            best = detections.pop(0)
            keep.append(best)

            # Filter remaining by IOU
            detections = [
                d for d in detections
                if self._iou(best.bbox, d.bbox) < self.NMS_IOU_THRESHOLD
            ]

        return keep

    def _expand_box(
        self,
        detection: SignatureDetection,
        img_w: int,
        img_h: int
    ) -> SignatureDetection:
        """Expand detection box by configured percentage for safety margin."""
        expand_w = int(detection.width * self.BOX_EXPANSION / 2)
        expand_h = int(detection.height * self.BOX_EXPANSION / 2)

        new_x = max(0, detection.x - expand_w)
        new_y = max(0, detection.y - expand_h)
        new_w = min(img_w - new_x, detection.width + 2 * expand_w)
        new_h = min(img_h - new_y, detection.height + 2 * expand_h)

        return SignatureDetection(
            x=new_x, y=new_y, width=new_w, height=new_h,
            confidence=detection.confidence,
            class_name=detection.class_name
        )

    @staticmethod
    def _iou(box1: Tuple[int, int, int, int], box2: Tuple[int, int, int, int]) -> float:
        """Calculate intersection over union of two boxes."""
        x1 = max(box1[0], box2[0])
        y1 = max(box1[1], box2[1])
        x2 = min(box1[2], box2[2])
        y2 = min(box1[3], box2[3])

        if x2 <= x1 or y2 <= y1:
            return 0.0

        intersection = (x2 - x1) * (y2 - y1)
        area1 = (box1[2] - box1[0]) * (box1[3] - box1[1])
        area2 = (box2[2] - box2[0]) * (box2[3] - box2[1])
        union = area1 + area2 - intersection

        return intersection / union if union > 0 else 0.0


class SignatureRedactor:
    """
    Redact detected signatures from images.

    Uses solid black fill (not blur) because signatures should be
    completely removed, not just obscured.
    """

    def __init__(self):
        pass

    def redact(
        self,
        image: np.ndarray,
        detections: List[SignatureDetection],
    ) -> np.ndarray:
        """
        Redact signatures from image with black boxes.

        Args:
            image: Image as numpy array
            detections: List of signature detections

        Returns:
            Image with signatures redacted
        """
        if not detections:
            return image

        result = image.copy()

        for det in detections:
            # Black fill
            result[det.y:det.y2, det.x:det.x2] = 0

        return result


class SignatureProtector:
    """
    Combined signature detection and redaction.

    Convenience class that wraps SignatureDetector and SignatureRedactor.
    """

    def __init__(
        self,
        models_dir: Path = None,
        confidence_threshold: float = None,
        **kwargs
    ):
        """
        Initialize signature protector.

        Args:
            models_dir: Ignored (kept for API compatibility)
            confidence_threshold: Minimum score for signature detection
            **kwargs: Additional parameters passed to SignatureDetector
        """
        self.detector = SignatureDetector(
            models_dir=models_dir,
            confidence_threshold=confidence_threshold,
            **kwargs
        )
        self.redactor = SignatureRedactor()

    @property
    def is_available(self) -> bool:
        return self.detector.is_available

    @property
    def is_initialized(self) -> bool:
        return self.detector.is_initialized

    @property
    def is_loading(self) -> bool:
        return self.detector.is_loading

    def start_loading(self) -> None:
        self.detector.start_loading()
    
    def await_ready(self, timeout: float = MODEL_LOAD_TIMEOUT) -> bool:
        return self.detector.await_ready(timeout)

    def process(
        self,
        image: np.ndarray,
    ) -> Tuple[SignatureRedactionResult, np.ndarray]:
        """
        Detect and redact signatures from image.

        Args:
            image: Image as numpy array

        Returns:
            (SignatureRedactionResult, redacted_image)
        """
        start_time = time.perf_counter()

        # Hash original for audit
        original_hash = hashlib.sha256(image.tobytes()).hexdigest()[:16]

        # Detect
        detections = self.detector.detect(image)

        # Redact
        if detections:
            redacted = self.redactor.redact(image, detections)
            redaction_applied = True
        else:
            redacted = image
            redaction_applied = False

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        result = SignatureRedactionResult(
            original_hash=original_hash,
            signatures_detected=len(detections),
            detections=detections,
            processing_time_ms=elapsed_ms,
            redaction_applied=redaction_applied,
        )

        return result, redacted
