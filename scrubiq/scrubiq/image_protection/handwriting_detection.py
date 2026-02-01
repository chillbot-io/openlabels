"""
Handwritten Text Detection for ScrubIQ.

Uses YOLOv8n-based object detection to find handwritten text regions in documents.
These regions are flagged for special handling because handwritten text often contains:
- Doctor's notes and annotations
- Patient signatures (biometric PHI)
- Patient-written information
- Margin notes with sensitive details

Unlike signatures which are always redacted, handwritten text regions are:
1. Detected and bounded
2. Passed to OCR for text extraction
3. The extracted text goes through PHI detection
4. Optionally redacted based on PHI findings

Model:
- yolov8n_handwriting_detection.onnx (~12MB) - YOLOv8n trained on handwritten text
  Source: armvectores/yolov8n_handwritten_text_detection on HuggingFace

Architecture:
    Image → Preprocessing → YOLOv8 Detection → NMS → Handwriting Regions
"""

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..constants import MODEL_LOAD_TIMEOUT
from typing import List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class HandwritingDetection:
    """A detected handwritten text region."""
    x: int
    y: int
    width: int
    height: int
    confidence: float
    class_name: str = "handwriting"
    
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
class HandwritingDetectionResult:
    """Result of handwriting detection."""
    original_hash: str
    regions_detected: int
    detections: List[HandwritingDetection]
    processing_time_ms: float
    
    def to_audit_dict(self) -> dict:
        """Convert to audit-safe dict."""
        return {
            "original_hash": self.original_hash,
            "regions_detected": self.regions_detected,
            "processing_time_ms": round(self.processing_time_ms, 1),
        }


class HandwritingDetector:
    """
    YOLOv8-based handwritten text detection.
    
    Detects handwritten text regions in document images for special processing.
    Unlike printed text, handwritten content often contains sensitive annotations
    and requires targeted OCR and PHI detection.
    
    Confidence threshold is lower (0.4) because:
    1. Handwriting varies greatly in style
    2. Missing handwritten PHI is worse than false positives
    3. Detected regions get further processing (OCR + PHI detection)
    """
    
    # Model filename - must match actual file in models directory
    MODEL_FILENAME = "yolov8n_handwriting_detection.onnx"
    
    # Detection parameters
    INPUT_SIZE = (640, 640)
    DEFAULT_CONFIDENCE_THRESHOLD = 0.4
    NMS_IOU_THRESHOLD = 0.45
    BOX_EXPANSION = 0.05  # Smaller expansion - we want tight bounds for OCR
    
    # Single class for this model
    CLASS_NAMES = ['handwriting']
    
    def __init__(
        self,
        models_dir: Path,
        confidence_threshold: float = None,
    ):
        """
        Initialize handwriting detector.
        
        Args:
            models_dir: Path to models directory
            confidence_threshold: Override default threshold (0.4)
        """
        self.models_dir = Path(models_dir)
        self.confidence_threshold = confidence_threshold or self.DEFAULT_CONFIDENCE_THRESHOLD
        
        self.model_path = self.models_dir / self.MODEL_FILENAME
        
        # Lazy-loaded ONNX session
        self._session = None
        self._initialized = False
        
        # Threading for async loading
        self._loading = False
        self._ready_event = threading.Event()
        self._load_error: Optional[Exception] = None
        self._lock = threading.Lock()
    
    @property
    def is_available(self) -> bool:
        """Check if model file exists."""
        return self.model_path.exists()
    
    @property
    def is_initialized(self) -> bool:
        """Check if model is loaded and ready."""
        return self._initialized
    
    @property
    def is_loading(self) -> bool:
        """Check if model is currently loading."""
        return self._loading and not self._initialized
    
    def start_loading(self) -> None:
        """Start loading model in background thread."""
        with self._lock:
            if self._initialized or self._loading:
                return
            self._loading = True
        
        thread = threading.Thread(target=self._background_load, daemon=True)
        thread.start()
    
    def _background_load(self) -> None:
        """Background thread for model loading."""
        try:
            self._load_model()
            self.warm_up()
        except Exception as e:
            self._load_error = e
            logger.error(f"Background handwriting detection loading failed: {e}")
        finally:
            self._ready_event.set()
    
    def await_ready(self, timeout: float = MODEL_LOAD_TIMEOUT) -> bool:
        """Wait for model to be ready."""
        if self._initialized:
            return True
        
        if not self._loading:
            self.start_loading()
        
        ready = self._ready_event.wait(timeout=timeout)
        
        if self._load_error:
            raise self._load_error
        
        return ready
    
    def _load_model(self) -> None:
        """Load ONNX model."""
        if not self.is_available:
            raise FileNotFoundError(
                f"Handwriting detection model not found at {self.model_path}. "
                "Download from HuggingFace: armvectores/yolov8n_handwritten_text_detection"
            )
        
        import onnxruntime as ort
        
        providers = ['CUDAExecutionProvider', 'CPUExecutionProvider']
        available = ort.get_available_providers()
        providers = [p for p in providers if p in available]
        
        logger.info(f"Loading handwriting detector from {self.model_path}")
        
        self._session = ort.InferenceSession(
            str(self.model_path),
            providers=providers
        )
        
        self._initialized = True
        logger.info(f"Handwriting detector loaded with providers: {providers}")
    
    def warm_up(self) -> None:
        """Warm up model with dummy inference."""
        if not self._initialized:
            return
        
        dummy = np.zeros((1, 3, 640, 640), dtype=np.float32)
        input_name = self._session.get_inputs()[0].name
        
        try:
            self._session.run(None, {input_name: dummy})
            logger.debug("Handwriting detector warmed up")
        except Exception as e:
            logger.warning(f"Handwriting detector warm-up failed: {e}")
    
    def _ensure_initialized(self) -> None:
        """Ensure model is loaded before detection."""
        if self._initialized:
            return
        
        with self._lock:
            if self._initialized:
                return
            self._load_model()
    
    def detect(
        self,
        image: np.ndarray,
        conf_threshold: float = None,
    ) -> List[HandwritingDetection]:
        """
        Detect handwritten text regions in image.
        
        Args:
            image: RGB image as numpy array (H, W, C)
            conf_threshold: Override default confidence threshold
            
        Returns:
            List of HandwritingDetection objects
        """
        self._ensure_initialized()
        
        conf_threshold = conf_threshold or self.confidence_threshold
        
        # Handle different image formats
        if len(image.shape) == 2:
            image = np.stack([image] * 3, axis=-1)
        elif image.shape[2] == 4:
            image = image[:, :, :3]
        
        orig_h, orig_w = image.shape[:2]
        
        # Preprocess
        input_tensor, scale, pad_w, pad_h = self._preprocess(image)
        
        # Inference
        input_name = self._session.get_inputs()[0].name
        outputs = self._session.run(None, {input_name: input_tensor})
        
        # Post-process
        detections = self._postprocess(
            outputs[0],
            orig_w, orig_h,
            scale, pad_w, pad_h,
            conf_threshold
        )
        
        # Expand boxes slightly
        detections = [self._expand_box(d, orig_w, orig_h) for d in detections]
        
        return detections
    
    def _preprocess(self, image: np.ndarray) -> Tuple[np.ndarray, float, int, int]:
        """Preprocess image for YOLOv8."""
        import cv2
        
        h, w = image.shape[:2]
        input_h, input_w = self.INPUT_SIZE
        
        scale = min(input_w / w, input_h / h)
        new_w, new_h = int(w * scale), int(h * scale)
        
        resized = cv2.resize(image, (new_w, new_h))
        
        pad_w = (input_w - new_w) // 2
        pad_h = (input_h - new_h) // 2
        
        padded = np.full((input_h, input_w, 3), 114, dtype=np.uint8)
        padded[pad_h:pad_h+new_h, pad_w:pad_w+new_w] = resized
        
        blob = padded.astype(np.float32) / 255.0
        blob = np.transpose(blob, (2, 0, 1))
        blob = np.expand_dims(blob, axis=0)
        
        return blob, scale, pad_w, pad_h
    
    def _postprocess(
        self,
        output: np.ndarray,
        orig_w: int,
        orig_h: int,
        scale: float,
        pad_w: int,
        pad_h: int,
        conf_threshold: float,
    ) -> List[HandwritingDetection]:
        """Post-process YOLOv8 output."""
        detections = []

        # Handle different output shapes
        # YOLOv8 output is typically (1, channels, num_detections) where channels=5 (x,y,w,h,conf)
        # We need rows to be detections, so transpose when channels dimension is small
        if len(output.shape) == 3:
            # If shape[1] is small (<=6 for x,y,w,h,conf,class), it's the channels dim
            # Transpose so each row is a detection with 5+ values
            if output.shape[1] <= 6 and output.shape[2] >= 1:
                boxes = output[0].T  # Transpose: (5, N) -> (N, 5)
            elif output.shape[1] < output.shape[2]:
                boxes = output[0].T
            else:
                boxes = output[0]
        else:
            boxes = output
        
        for box in boxes:
            if len(box) < 5:
                continue
            
            x_center, y_center, bw, bh = box[:4]
            
            if len(box) == 5:
                conf = box[4]
            else:
                conf = np.max(box[4:])
            
            if conf < conf_threshold:
                continue
            
            x1 = x_center - bw / 2
            y1 = y_center - bh / 2
            
            x1 = (x1 - pad_w) / scale
            y1 = (y1 - pad_h) / scale
            bw = bw / scale
            bh = bh / scale
            
            x1 = max(0, int(x1))
            y1 = max(0, int(y1))
            bw = min(orig_w - x1, int(bw))
            bh = min(orig_h - y1, int(bh))
            
            if bw > 0 and bh > 0:
                detections.append(HandwritingDetection(
                    x=x1, y=y1, width=bw, height=bh,
                    confidence=float(conf),
                    class_name="handwriting"
                ))
        
        detections = self._nms(detections)
        
        return detections
    
    def _nms(self, detections: List[HandwritingDetection]) -> List[HandwritingDetection]:
        """Non-maximum suppression."""
        if not detections:
            return []
        
        detections = sorted(detections, key=lambda d: d.confidence, reverse=True)
        
        keep = []
        while detections:
            best = detections.pop(0)
            keep.append(best)
            
            detections = [
                d for d in detections
                if self._iou(best.bbox, d.bbox) < self.NMS_IOU_THRESHOLD
            ]
        
        return keep
    
    def _expand_box(
        self,
        detection: HandwritingDetection,
        img_w: int,
        img_h: int
    ) -> HandwritingDetection:
        """Expand detection box by configured percentage."""
        expand_w = int(detection.width * self.BOX_EXPANSION / 2)
        expand_h = int(detection.height * self.BOX_EXPANSION / 2)
        
        new_x = max(0, detection.x - expand_w)
        new_y = max(0, detection.y - expand_h)
        new_w = min(img_w - new_x, detection.width + 2 * expand_w)
        new_h = min(img_h - new_y, detection.height + 2 * expand_h)
        
        return HandwritingDetection(
            x=new_x, y=new_y, width=new_w, height=new_h,
            confidence=detection.confidence,
            class_name=detection.class_name
        )
    
    @staticmethod
    def _iou(box1: Tuple[int, int, int, int], box2: Tuple[int, int, int, int]) -> float:
        """Calculate intersection over union."""
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
    
    def process(
        self,
        image: np.ndarray,
    ) -> HandwritingDetectionResult:
        """
        Detect handwritten text regions in image.
        
        Args:
            image: RGB image as numpy array
            
        Returns:
            HandwritingDetectionResult with detected regions
        """
        start_time = time.perf_counter()
        
        original_hash = hashlib.sha256(image.tobytes()).hexdigest()[:16]
        
        detections = self.detect(image)
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return HandwritingDetectionResult(
            original_hash=original_hash,
            regions_detected=len(detections),
            detections=detections,
            processing_time_ms=elapsed_ms,
        )
