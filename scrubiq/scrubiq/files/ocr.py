"""
OCR engine using RapidOCR with local ONNX models.

RapidOCR is PaddleOCR's models pre-converted to ONNX, running on onnxruntime.
This aligns with ScrubIQ's all-ONNX inference stack.

Models required in models_dir/rapidocr/:
- det.onnx (~4.5 MB) - Text region detection
- rec.onnx (~11 MB) - Text recognition  
- cls.onnx (~1.5 MB) - Orientation classification
"""

import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple, Union, TYPE_CHECKING
import numpy as np
from intervaltree import IntervalTree

from ..constants import MODEL_LOAD_TIMEOUT

if TYPE_CHECKING:
    from PIL import Image

logger = logging.getLogger(__name__)


def _clean_ocr_text(text: str) -> str:
    """
    Clean up common OCR artifacts from structured documents.
    
    Fixes:
    - Stuck field codes: "15SEX:M" → "15 SEX: M"  
    - Missing spaces after colons: "DOB:01/01/90" → "DOB: 01/01/90"
    - Numbers stuck to words: "18EYES" → "18 EYES"
    - Field codes with letters: "4dDLN" → "4d DLN"
    """
    # Add space between digits (optionally followed by lowercase) and uppercase letters
    # 15SEX → 15 SEX, 18EYES → 18 EYES, 4dDLN → 4d DLN
    text = re.sub(r'(\d[a-z]?)([A-Z]{2,})', r'\1 \2', text)
    
    # Add space after colon if followed by letter/digit without space
    # DOB:01/01 → DOB: 01/01, SEX:M → SEX: M  
    text = re.sub(r':([A-Za-z0-9])', r': \1', text)
    
    return text


@dataclass
class OCRBlock:
    """
    A single text block from OCR with coordinates.
    
    Represents one detected text region with its bounding box,
    enabling mapping of PHI spans back to image coordinates for redaction.
    """
    text: str
    bbox: List[List[float]]  # [[x1,y1], [x2,y2], [x3,y3], [x4,y4]] quadrilateral
    confidence: float
    
    @property
    def bounding_rect(self) -> Tuple[int, int, int, int]:
        """
        Convert quadrilateral to axis-aligned rectangle.
        
        Returns:
            (x1, y1, x2, y2) where (x1,y1) is top-left and (x2,y2) is bottom-right
        """
        xs = [p[0] for p in self.bbox]
        ys = [p[1] for p in self.bbox]
        return (int(min(xs)), int(min(ys)), int(max(xs)), int(max(ys)))


@dataclass
class OCRResult:
    """
    Complete OCR result with text-to-coordinate mapping.

    Contains the full extracted text, individual blocks with coordinates,
    and an offset map that links character positions in full_text back to
    their source blocks. This enables mapping PHI spans to image regions.

    Offset map format: List of (start_char, end_char, block_index) tuples.

    Example:
        Block 0: "SAMPLE"        chars 0-5
        Block 1: "ANDREW JASON"  chars 7-18   (char 6 is newline)
        Block 2: "01/07/1973"    chars 20-29  (char 19 is newline)

        offset_map = [(0, 6, 0), (7, 19, 1), (20, 30, 2)]

        When PHI detection finds "01/07/1973" at chars 20-30, we look up
        offset_map and find it maps to block_idx=2, which has bounding box.

    Uses IntervalTree for O(log n + k) lookup instead of O(n) linear search.
    """
    full_text: str
    blocks: List[OCRBlock]
    offset_map: List[Tuple[int, int, int]]  # (start_char, end_char, block_index)
    confidence: float
    _interval_tree: IntervalTree = field(default_factory=IntervalTree, repr=False, compare=False)

    def __post_init__(self):
        """Build interval tree for fast span lookups."""
        if self.offset_map and not self._interval_tree:
            self._interval_tree = IntervalTree()
            for (block_start, block_end, block_idx) in self.offset_map:
                if block_start < block_end:  # IntervalTree requires non-empty intervals
                    self._interval_tree[block_start:block_end] = block_idx

    def get_blocks_for_span(self, start: int, end: int) -> List[OCRBlock]:
        """
        Find all OCR blocks that overlap with a character span.

        Uses IntervalTree for O(log n + k) performance where k is number of matches,
        instead of O(n) linear search through all blocks.

        Args:
            start: Start character position in full_text
            end: End character position in full_text

        Returns:
            List of OCRBlocks whose text overlaps the given span
        """
        if not self._interval_tree:
            # Fallback to linear search if tree not built
            overlapping = []
            for (block_start, block_end, block_idx) in self.offset_map:
                if start < block_end and end > block_start:
                    overlapping.append(self.blocks[block_idx])
            return overlapping

        # Use interval tree for O(log n + k) lookup
        overlaps = self._interval_tree[start:end]
        return [self.blocks[interval.data] for interval in overlaps]


class OCREngine:
    """
    RapidOCR wrapper using local ONNX models.
    
    Provides lazy loading and pre-warming capability for background
    initialization after vault unlock.
    
    Usage:
        engine = OCREngine(models_dir)
        text = engine.extract_text(image)  # PIL Image or path
        
    Pre-warming (call after unlock):
        engine.warm_up()
        
    Lazy loading (for non-blocking startup):
        engine.start_loading()  # Starts background thread
        engine.await_ready(timeout=30)  # Blocks until ready
    """
    
    def __init__(self, models_dir: Path):
        """
        Initialize OCR engine.
        
        Args:
            models_dir: Path to models directory containing rapidocr/ subfolder
        """
        self.models_dir = models_dir
        self.rapidocr_dir = models_dir / "rapidocr"
        self._ocr = None  # Lazy load
        self._initialized = False
        self._loading = False
        self._ready_event = threading.Event()
        self._load_error: Optional[Exception] = None
        self._lock = threading.Lock()
        
    @property
    def has_custom_models(self) -> bool:
        """Check if custom RapidOCR models are present in models_dir."""
        required_models = ["det.onnx", "rec.onnx", "cls.onnx"]
        return all((self.rapidocr_dir / m).exists() for m in required_models)

    @property
    def is_available(self) -> bool:
        """Check if RapidOCR is available (either custom or bundled models)."""
        # Custom models take priority
        if self.has_custom_models:
            return True
        # Otherwise check if rapidocr-onnxruntime is installed (has bundled models)
        try:
            import rapidocr_onnxruntime
            return True
        except ImportError:
            return False
    
    @property
    def is_initialized(self) -> bool:
        """Check if OCR engine has been loaded."""
        return self._initialized
    
    @property
    def is_loading(self) -> bool:
        """Check if OCR engine is currently loading."""
        return self._loading and not self._initialized
    
    def start_loading(self) -> None:
        """
        Start loading models in background thread.
        
        Non-blocking. Use await_ready() to wait for completion.
        """
        with self._lock:
            if self._initialized or self._loading:
                return
            self._loading = True
        
        thread = threading.Thread(target=self._background_load, daemon=True)
        thread.start()
    
    def _background_load(self) -> None:
        """Background thread for model loading."""
        try:
            self._ensure_initialized()
            # Also warm up to reduce first-call latency
            self.warm_up()
        except Exception as e:
            self._load_error = e
            logger.error(f"Background OCR loading failed: {e}")
        finally:
            self._ready_event.set()
    
    def await_ready(self, timeout: float = MODEL_LOAD_TIMEOUT) -> bool:
        """
        Wait for models to be ready.
        
        Args:
            timeout: Maximum seconds to wait
            
        Returns:
            True if ready, False if timeout
            
        Raises:
            Exception if loading failed
        """
        if self._initialized:
            return True
        
        # Start loading if not already started
        if not self._loading:
            self.start_loading()
        
        ready = self._ready_event.wait(timeout=timeout)
        
        if self._load_error:
            raise self._load_error
        
        return ready
    
    def _ensure_initialized(self) -> None:
        """Lazy-load RapidOCR on first use."""
        if self._ocr is not None:
            return

        if not self.is_available:
            raise ImportError(
                "rapidocr-onnxruntime not installed. "
                "Run: pip install rapidocr-onnxruntime"
            )

        try:
            from rapidocr_onnxruntime import RapidOCR

            # Use custom models if available, otherwise use bundled models
            if self.has_custom_models:
                logger.info(f"Loading RapidOCR with custom models from {self.rapidocr_dir}")
                self._ocr = RapidOCR(
                    det_model_path=str(self.rapidocr_dir / "det.onnx"),
                    rec_model_path=str(self.rapidocr_dir / "rec.onnx"),
                    cls_model_path=str(self.rapidocr_dir / "cls.onnx"),
                )
            else:
                logger.info("Loading RapidOCR with bundled models")
                self._ocr = RapidOCR()

            self._initialized = True
            logger.info("RapidOCR initialized successfully")

        except ImportError:
            raise ImportError(
                "rapidocr-onnxruntime not installed. "
                "Run: pip install rapidocr-onnxruntime"
            )
        except Exception as e:
            logger.error(f"Failed to initialize RapidOCR: {e}")
            raise
    
    def warm_up(self) -> bool:
        """
        Pre-warm OCR engine by loading models and running inference on dummy image.
        
        Call this in background after vault unlock to reduce first-call latency.
        First real OCR call typically takes 2-3s without warm-up.
        
        Returns:
            True if warm-up successful, False otherwise
        """
        try:
            self._ensure_initialized()
            
            # Run inference on tiny image to fully load models
            dummy = np.zeros((10, 10, 3), dtype=np.uint8)
            _ = self._ocr(dummy)
            
            logger.info("RapidOCR warm-up complete")
            return True
            
        except Exception as e:
            logger.warning(f"RapidOCR warm-up failed: {e}")
            return False
    
    def extract_text(
        self, 
        image: Union[str, Path, "np.ndarray", "Image.Image"],
    ) -> str:
        """
        Extract text from image.
        
        Args:
            image: Can be:
                - Path to image file (str or Path)
                - numpy array (H, W, C) in RGB or BGR
                - PIL Image
                
        Returns:
            Extracted text with lines joined by newlines.
            Empty string if no text detected.
            
        Raises:
            FileNotFoundError: If models not available
            ImportError: If rapidocr-onnxruntime not installed
        """
        self._ensure_initialized()
        
        # Convert Path to string for RapidOCR
        if isinstance(image, Path):
            image = str(image)
        
        # Run OCR
        result, _ = self._ocr(image)
        
        if not result:
            return ""
        
        # Result format: [(bbox, text, confidence), ...]
        # bbox is [[x1,y1], [x2,y2], [x3,y3], [x4,y4]] (quadrilateral)
        # Sort by y-coordinate (top of bounding box) for reading order
        # Then by x-coordinate for same line
        
        def sort_key(item):
            bbox = item[0]
            # Use top-left corner: bbox[0] = [x1, y1]
            y_top = min(bbox[0][1], bbox[1][1], bbox[2][1], bbox[3][1])
            x_left = min(bbox[0][0], bbox[1][0], bbox[2][0], bbox[3][0])
            # Group into approximate lines (within 20px = same line)
            line_group = int(y_top / 20)
            return (line_group, x_left)
        
        result.sort(key=sort_key)
        
        # Group blocks into lines and join with proper spacing
        lines = []
        current_line_parts = []
        current_line_group = None
        
        for item in result:
            bbox = item[0]
            text = item[1]
            y_top = min(bbox[0][1], bbox[1][1], bbox[2][1], bbox[3][1])
            line_group = int(y_top / 20)
            
            if current_line_group is None:
                current_line_group = line_group
                current_line_parts.append(text)
            elif line_group == current_line_group:
                # Same line - add with space
                current_line_parts.append(text)
            else:
                # New line - flush current and start new
                lines.append(' '.join(current_line_parts))
                current_line_parts = [text]
                current_line_group = line_group
        
        # Flush final line
        if current_line_parts:
            lines.append(' '.join(current_line_parts))
        
        return _clean_ocr_text('\n'.join(lines))
    
    def extract_text_with_confidence(
        self,
        image: Union[str, Path, "np.ndarray", "Image.Image"],
    ) -> tuple[str, float]:
        """
        Extract text with average confidence score.
        
        Returns:
            Tuple of (text, average_confidence).
            Confidence is 0.0 if no text detected.
        """
        self._ensure_initialized()
        
        if isinstance(image, Path):
            image = str(image)
        
        result, _ = self._ocr(image)
        
        if not result:
            return "", 0.0
        
        # Sort for reading order
        def sort_key(item):
            bbox = item[0]
            y_top = min(bbox[0][1], bbox[1][1], bbox[2][1], bbox[3][1])
            x_left = min(bbox[0][0], bbox[1][0], bbox[2][0], bbox[3][0])
            line_group = int(y_top / 20)
            return (line_group, x_left)
        
        result.sort(key=sort_key)
        
        confidences = [item[2] for item in result]
        
        # Group blocks into lines and join with proper spacing
        lines = []
        current_line_parts = []
        current_line_group = None
        
        for item in result:
            bbox = item[0]
            text = item[1]
            y_top = min(bbox[0][1], bbox[1][1], bbox[2][1], bbox[3][1])
            line_group = int(y_top / 20)
            
            if current_line_group is None:
                current_line_group = line_group
                current_line_parts.append(text)
            elif line_group == current_line_group:
                current_line_parts.append(text)
            else:
                lines.append(' '.join(current_line_parts))
                current_line_parts = [text]
                current_line_group = line_group
        
        if current_line_parts:
            lines.append(' '.join(current_line_parts))
        
        text = _clean_ocr_text('\n'.join(lines))
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        
        return text, avg_confidence
    
    def extract_with_coordinates(
        self,
        image: Union[str, Path, "np.ndarray", "Image.Image"],
    ) -> OCRResult:
        """
        Extract text with bounding box coordinates.
        
        Returns OCRResult with full_text, blocks, and offset_map for
        mapping PHI spans back to image coordinates for visual redaction.
        
        Args:
            image: Can be:
                - Path to image file (str or Path)
                - numpy array (H, W, C) in RGB or BGR
                - PIL Image
                
        Returns:
            OCRResult with full text, blocks with coordinates, and offset map.
            
        Raises:
            FileNotFoundError: If models not available
            ImportError: If rapidocr-onnxruntime not installed
        """
        self._ensure_initialized()
        
        if isinstance(image, Path):
            image = str(image)
        
        result, _ = self._ocr(image)
        
        if not result:
            return OCRResult(
                full_text="",
                blocks=[],
                offset_map=[],
                confidence=0.0,
            )
        
        # Sort by reading order (top-to-bottom, left-to-right)
        def sort_key(item):
            bbox = item[0]
            y_top = min(p[1] for p in bbox)
            x_left = min(p[0] for p in bbox)
            # Group into approximate lines (within 20px = same line)
            line_group = int(y_top / 20)
            return (line_group, x_left)
        
        result.sort(key=sort_key)
        
        # Build blocks and offset map
        blocks = []
        offset_map = []
        confidences = []
        
        for i, (bbox, text, conf) in enumerate(result):
            blocks.append(OCRBlock(
                text=text,
                bbox=bbox,
                confidence=conf,
            ))
            confidences.append(conf)
        
        # Build text with proper spacing:
        # - Same line (same line_group) → space between blocks
        # - Different lines → newline between blocks
        lines = []
        current_line_parts = []
        current_line_group = None
        
        for i, block in enumerate(blocks):
            y_top = min(p[1] for p in block.bbox)
            line_group = int(y_top / 20)
            
            if current_line_group is None:
                current_line_group = line_group
                current_line_parts.append(block.text)
            elif line_group == current_line_group:
                # Same line - add with space
                current_line_parts.append(block.text)
            else:
                # New line - flush current line and start new
                lines.append(' '.join(current_line_parts))
                current_line_parts = [block.text]
                current_line_group = line_group
        
        # Flush final line
        if current_line_parts:
            lines.append(' '.join(current_line_parts))
        
        # Join lines - DON'T apply _clean_ocr_text() here because it would
        # break the offset_map alignment (it adds characters like "15SEX" → "15 SEX")
        # The spacing fix between blocks is the important one for readability.
        # OCR artifact cleanup happens elsewhere in the pipeline.
        full_text = '\n'.join(lines)
        
        # Build offset map for the properly-spaced text
        offset_map = []
        current_offset = 0
        line_idx = 0
        block_in_line = 0
        
        for i, block in enumerate(blocks):
            y_top = min(p[1] for p in block.bbox)
            line_group = int(y_top / 20)
            
            # Check if we've moved to a new line
            if i > 0:
                prev_y_top = min(p[1] for p in blocks[i-1].bbox)
                prev_line_group = int(prev_y_top / 20)
                if line_group != prev_line_group:
                    # New line - add newline offset
                    current_offset += 1  # for \n
                    block_in_line = 0
                else:
                    # Same line - add space offset
                    current_offset += 1  # for space
            
            start = current_offset
            end = current_offset + len(block.text)
            offset_map.append((start, end, i))
            current_offset = end
        
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        
        return OCRResult(
            full_text=full_text,
            blocks=blocks,
            offset_map=offset_map,
            confidence=avg_confidence,
        )
    
    def extract_with_layout(
        self,
        image: Union[str, Path, "np.ndarray", "Image.Image"],
        apply_layout_processing: bool = False,
    ) -> OCRResult:
        """
        Extract text with bounding boxes and optional layout processing.
        
        .. deprecated::
            The apply_layout_processing parameter uses the deprecated layout.py.
            For document intelligence, use EnhancedOCRProcessor directly in
            your extraction pipeline, which is wired up in ImageExtractor
            and PDFExtractor by default.
        
        Args:
            image: Image to process
            apply_layout_processing: Whether to apply layout-aware cleanup
                (deprecated - use EnhancedOCRProcessor instead)
            
        Returns:
            OCRResult with text and bounding boxes
        """
        # Get raw OCR result (with proper spacing from our fixed extract_with_coordinates)
        result = self.extract_with_coordinates(image)
        
        if not apply_layout_processing or not result.blocks:
            return result
        
        # Apply legacy layout processing (deprecated)
        try:
            from .layout import process_structured_document
            import warnings
            warnings.warn(
                "apply_layout_processing=True uses deprecated layout.py. "
                "Use EnhancedOCRProcessor for document intelligence.",
                DeprecationWarning,
                stacklevel=2
            )
            return process_structured_document(result)
        except Exception as e:
            logger.warning(f"Layout processing failed, using raw OCR: {e}")
            return result
