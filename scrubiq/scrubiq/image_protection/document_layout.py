"""
Document Layout Analysis for ScrubIQ.

Uses DocLayout-YOLO to detect document structure including titles, text blocks,
tables, figures, headers, footers, and equations. This enables:
1. Smarter OCR post-processing for structured documents (ID cards, forms)
2. Better understanding of document regions for targeted PHI detection
3. Improved handling of tables and structured data

Model:
- doclayout_yolo_docstructbench_imgsz1024.onnx (~75MB)
  Source: wybxc/DocLayout-YOLO-DocStructBench-onnx on HuggingFace
  License: Apache 2.0

Architecture:
    Image → Preprocessing → DocLayout-YOLO → NMS → Layout Regions
"""

import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

from ..constants import MODEL_LOAD_TIMEOUT

logger = logging.getLogger(__name__)


class LayoutClass(Enum):
    """Document layout element classes."""
    TITLE = 0
    TEXT = 1
    ABANDON = 2  # Background/ignore
    FIGURE = 3
    FIGURE_CAPTION = 4
    TABLE = 5
    TABLE_CAPTION = 6
    HEADER = 7
    FOOTER = 8
    REFERENCE = 9
    EQUATION = 10


# Human-readable names
LAYOUT_CLASS_NAMES = {
    LayoutClass.TITLE: "title",
    LayoutClass.TEXT: "text",
    LayoutClass.ABANDON: "abandon",
    LayoutClass.FIGURE: "figure",
    LayoutClass.FIGURE_CAPTION: "figure_caption",
    LayoutClass.TABLE: "table",
    LayoutClass.TABLE_CAPTION: "table_caption",
    LayoutClass.HEADER: "header",
    LayoutClass.FOOTER: "footer",
    LayoutClass.REFERENCE: "reference",
    LayoutClass.EQUATION: "equation",
}


@dataclass
class LayoutRegion:
    """A detected document layout region."""
    x: int
    y: int
    width: int
    height: int
    confidence: float
    layout_class: LayoutClass
    
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
    
    @property
    def class_name(self) -> str:
        return LAYOUT_CLASS_NAMES.get(self.layout_class, "unknown")
    
    @property
    def center(self) -> Tuple[int, int]:
        return (self.x + self.width // 2, self.y + self.height // 2)
    
    def to_dict(self) -> dict:
        return {
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "confidence": round(self.confidence, 3),
            "class": self.class_name,
        }


@dataclass
class LayoutAnalysisResult:
    """Result of document layout analysis."""
    regions: List[LayoutRegion]
    processing_time_ms: float
    image_width: int
    image_height: int
    
    def get_regions_by_class(self, layout_class: LayoutClass) -> List[LayoutRegion]:
        """Get all regions of a specific class."""
        return [r for r in self.regions if r.layout_class == layout_class]
    
    @property
    def has_tables(self) -> bool:
        return any(r.layout_class == LayoutClass.TABLE for r in self.regions)
    
    @property
    def has_figures(self) -> bool:
        return any(r.layout_class == LayoutClass.FIGURE for r in self.regions)
    
    def to_dict(self) -> dict:
        return {
            "num_regions": len(self.regions),
            "processing_time_ms": round(self.processing_time_ms, 1),
            "image_size": [self.image_width, self.image_height],
            "classes_found": list(set(r.class_name for r in self.regions)),
        }


class DocumentLayoutDetector:
    """
    DocLayout-YOLO based document layout analysis.
    
    Detects document structure elements to enable smarter OCR and PHI detection.
    Particularly useful for:
    - ID cards (detecting name/address regions)
    - Medical forms (detecting patient info sections)
    - Tables (lab results, medication lists)
    """
    
    # Model filename - must match actual file in models directory
    MODEL_FILENAME = "yolo_doclayout.onnx"
    
    # Detection parameters
    INPUT_SIZE = (1024, 1024)  # This model uses 1024x1024
    DEFAULT_CONFIDENCE_THRESHOLD = 0.35
    NMS_IOU_THRESHOLD = 0.45
    
    # Number of classes in this model
    NUM_CLASSES = 11
    
    def __init__(
        self,
        models_dir: Path,
        confidence_threshold: float = None,
    ):
        """
        Initialize document layout detector.
        
        Args:
            models_dir: Path to models directory
            confidence_threshold: Override default threshold (0.35)
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
            logger.error(f"Background document layout loading failed: {e}")
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
                f"Document layout model not found at {self.model_path}. "
                "Download from HuggingFace: wybxc/DocLayout-YOLO-DocStructBench-onnx"
            )
        
        import onnxruntime as ort
        
        providers = ['CUDAExecutionProvider', 'CPUExecutionProvider']
        available = ort.get_available_providers()
        providers = [p for p in providers if p in available]
        
        logger.info(f"Loading document layout detector from {self.model_path}")
        
        self._session = ort.InferenceSession(
            str(self.model_path),
            providers=providers
        )
        
        self._initialized = True
        logger.info(f"Document layout detector loaded with providers: {providers}")
    
    def warm_up(self) -> None:
        """Warm up model with dummy inference."""
        if not self._initialized:
            return
        
        dummy = np.zeros((1, 3, 1024, 1024), dtype=np.float32)
        input_name = self._session.get_inputs()[0].name
        
        try:
            self._session.run(None, {input_name: dummy})
            logger.debug("Document layout detector warmed up")
        except Exception as e:
            logger.warning(f"Document layout detector warm-up failed: {e}")
    
    def _ensure_initialized(self) -> None:
        """Ensure model is loaded before detection."""
        if self._initialized:
            return
        
        with self._lock:
            if self._initialized:
                return
            self._load_model()
    
    def analyze(
        self,
        image: np.ndarray,
        conf_threshold: float = None,
    ) -> LayoutAnalysisResult:
        """
        Analyze document layout.
        
        Args:
            image: RGB image as numpy array (H, W, C)
            conf_threshold: Override default confidence threshold
            
        Returns:
            LayoutAnalysisResult with detected regions
        """
        start_time = time.perf_counter()
        
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
        regions = self._postprocess(
            outputs[0],
            orig_w, orig_h,
            scale, pad_w, pad_h,
            conf_threshold
        )
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return LayoutAnalysisResult(
            regions=regions,
            processing_time_ms=elapsed_ms,
            image_width=orig_w,
            image_height=orig_h,
        )
    
    def _preprocess(self, image: np.ndarray) -> Tuple[np.ndarray, float, int, int]:
        """Preprocess image for DocLayout-YOLO."""
        import cv2
        
        h, w = image.shape[:2]
        input_h, input_w = self.INPUT_SIZE
        
        # Calculate scale maintaining aspect ratio
        scale = min(input_w / w, input_h / h)
        new_w, new_h = int(w * scale), int(h * scale)
        
        # Resize
        resized = cv2.resize(image, (new_w, new_h))
        
        # Pad to target size (center padding)
        pad_w = (input_w - new_w) // 2
        pad_h = (input_h - new_h) // 2
        
        padded = np.full((input_h, input_w, 3), 114, dtype=np.uint8)
        padded[pad_h:pad_h+new_h, pad_w:pad_w+new_w] = resized
        
        # Normalize and transpose: HWC -> NCHW, [0,255] -> [0,1]
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
    ) -> List[LayoutRegion]:
        """Post-process DocLayout-YOLO output."""
        regions = []
        
        # Handle different output shapes
        # Expected: [batch, 4+num_classes, num_boxes] or [batch, num_boxes, 4+num_classes]
        if len(output.shape) == 3:
            # Check which dimension has the class info
            if output.shape[1] == 4 + self.NUM_CLASSES:
                boxes = output[0].T  # -> [num_boxes, 4+num_classes]
            elif output.shape[2] == 4 + self.NUM_CLASSES:
                boxes = output[0]
            else:
                # Try transpose
                boxes = output[0].T
        else:
            boxes = output
        
        for box in boxes:
            if len(box) < 5:
                continue
            
            x_center, y_center, bw, bh = box[:4]
            class_scores = box[4:]
            
            # Get best class
            if len(class_scores) > 0:
                class_id = int(np.argmax(class_scores))
                conf = float(class_scores[class_id])
            else:
                continue
            
            if conf < conf_threshold:
                continue
            
            # Skip 'abandon' class (background)
            if class_id == LayoutClass.ABANDON.value:
                continue
            
            # Convert from center format to corner format
            x1 = x_center - bw / 2
            y1 = y_center - bh / 2
            
            # Remove padding and scale back to original
            x1 = (x1 - pad_w) / scale
            y1 = (y1 - pad_h) / scale
            bw = bw / scale
            bh = bh / scale
            
            # Clip to image bounds
            x1 = max(0, int(x1))
            y1 = max(0, int(y1))
            bw = min(orig_w - x1, int(bw))
            bh = min(orig_h - y1, int(bh))
            
            if bw > 0 and bh > 0:
                try:
                    layout_class = LayoutClass(class_id)
                except ValueError:
                    layout_class = LayoutClass.TEXT  # Default to text
                
                regions.append(LayoutRegion(
                    x=x1, y=y1, width=bw, height=bh,
                    confidence=conf,
                    layout_class=layout_class
                ))
        
        # Apply NMS per class
        regions = self._nms_per_class(regions)
        
        # Sort by position (top-to-bottom, left-to-right)
        regions.sort(key=lambda r: (r.y, r.x))
        
        return regions
    
    def _nms_per_class(self, regions: List[LayoutRegion]) -> List[LayoutRegion]:
        """Apply NMS separately for each class."""
        if not regions:
            return []
        
        # Group by class
        by_class = {}
        for r in regions:
            if r.layout_class not in by_class:
                by_class[r.layout_class] = []
            by_class[r.layout_class].append(r)
        
        # NMS per class
        result = []
        for class_regions in by_class.values():
            result.extend(self._nms(class_regions))
        
        return result
    
    def _nms(self, regions: List[LayoutRegion]) -> List[LayoutRegion]:
        """Non-maximum suppression."""
        if not regions:
            return []
        
        regions = sorted(regions, key=lambda r: r.confidence, reverse=True)
        
        keep = []
        while regions:
            best = regions.pop(0)
            keep.append(best)
            
            regions = [
                r for r in regions
                if self._iou(best.bbox, r.bbox) < self.NMS_IOU_THRESHOLD
            ]
        
        return keep
    
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
