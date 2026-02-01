"""
Enhanced OCR post-processing with layout awareness.

Combines document layout analysis with OCR to improve text extraction quality,
especially for structured documents like ID cards, forms, and tables.

Pipeline:
1. Run OCR to get raw text blocks
2. Run layout analysis to detect document regions
3. Detect document type using templates
4. Apply document-specific post-processing
5. Use layout regions to improve text grouping and spacing
6. Return cleaned text with better structure
"""

import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple, TYPE_CHECKING

import numpy as np

from .document_templates import (
    detect_document_type,
    parse_document,
    get_parser,
    DocumentType,
)

if TYPE_CHECKING:
    from ..image_protection.document_layout import (
        DocumentLayoutDetector, 
        LayoutAnalysisResult, 
        LayoutRegion,
    )
    from .ocr import OCRResult, OCRBlock

logger = logging.getLogger(__name__)

# ID card document types for quick classification
ID_CARD_TYPES = frozenset({
    DocumentType.DRIVERS_LICENSE,
    DocumentType.STATE_ID,
    DocumentType.PASSPORT,
    DocumentType.PASSPORT_CARD,
    DocumentType.MILITARY_ID,
    DocumentType.INSURANCE_COMMERCIAL,
    DocumentType.INSURANCE_MEDICARE,
    DocumentType.INSURANCE_MEDICAID,
    DocumentType.INSURANCE_TRICARE,
})


@dataclass
class EnhancedOCRResult:
    """OCR result with layout-enhanced processing."""
    raw_text: str
    enhanced_text: str
    document_type: DocumentType
    is_id_card: bool
    layout_regions: int
    enhancements_applied: List[str]
    phi_fields: dict = None


def improve_spacing_with_layout(
    ocr_blocks: List["OCRBlock"],
    layout_regions: List["LayoutRegion"],
    line_threshold: int = 20,
) -> str:
    """
    Use layout regions to improve text spacing and grouping.
    
    Groups OCR blocks by their containing layout region, then
    assembles text with proper spacing based on spatial gaps.
    """
    if not ocr_blocks:
        return ""
    
    # If no layout regions, fall back to basic spatial grouping
    if not layout_regions:
        return _basic_spatial_grouping(ocr_blocks, line_threshold)
    
    # Map OCR blocks to layout regions
    block_to_region = {}
    for i, block in enumerate(ocr_blocks):
        block_rect = block.bounding_rect
        block_center = (
            (block_rect[0] + block_rect[2]) // 2,
            (block_rect[1] + block_rect[3]) // 2
        )
        
        # Find containing region
        for region in layout_regions:
            if (region.x <= block_center[0] <= region.x2 and
                region.y <= block_center[1] <= region.y2):
                block_to_region[i] = region
                break
    
    # Group blocks by region, then by line within region
    region_texts = {}
    unassigned_blocks = []
    
    for i, block in enumerate(ocr_blocks):
        if i in block_to_region:
            region = block_to_region[i]
            region_key = (region.x, region.y, region.layout_class.value)
            if region_key not in region_texts:
                region_texts[region_key] = []
            region_texts[region_key].append((block, i))
        else:
            unassigned_blocks.append((block, i))
    
    # Build text from regions (sorted by position)
    result_parts = []
    
    sorted_regions = sorted(region_texts.keys(), key=lambda k: (k[1], k[0]))  # y, then x
    
    for region_key in sorted_regions:
        blocks = region_texts[region_key]
        region_text = _assemble_blocks(blocks, line_threshold)
        if region_text.strip():
            result_parts.append(region_text)
    
    # Add unassigned blocks
    if unassigned_blocks:
        unassigned_text = _assemble_blocks(unassigned_blocks, line_threshold)
        if unassigned_text.strip():
            result_parts.append(unassigned_text)
    
    return '\n'.join(result_parts)


def _basic_spatial_grouping(
    ocr_blocks: List["OCRBlock"],
    line_threshold: int = 20
) -> str:
    """
    Basic spatial grouping without layout information.
    
    Groups blocks into lines based on Y coordinate proximity,
    then orders left-to-right within each line.
    """
    if not ocr_blocks:
        return ""
    
    # Sort by Y (top), then X (left)
    def sort_key(block):
        rect = block.bounding_rect
        y_top = rect[1]
        x_left = rect[0]
        line_group = y_top // line_threshold
        return (line_group, x_left)
    
    sorted_blocks = sorted(ocr_blocks, key=sort_key)
    
    # Group into lines
    lines = []
    current_line = []
    current_line_y = None
    
    for block in sorted_blocks:
        rect = block.bounding_rect
        y_top = rect[1]
        line_group = y_top // line_threshold
        
        if current_line_y is None or line_group != current_line_y:
            if current_line:
                lines.append(current_line)
            current_line = [block]
            current_line_y = line_group
        else:
            current_line.append(block)
    
    if current_line:
        lines.append(current_line)
    
    # Assemble text with space detection
    result_lines = []
    for line in lines:
        line_text = _assemble_line_with_gaps(line)
        if line_text.strip():
            result_lines.append(line_text)
    
    return '\n'.join(result_lines)


def _assemble_blocks(
    blocks_with_idx: List[Tuple["OCRBlock", int]],
    line_threshold: int
) -> str:
    """Assemble blocks into text, respecting line breaks."""
    if not blocks_with_idx:
        return ""
    
    blocks = [b for b, _ in blocks_with_idx]
    return _basic_spatial_grouping(blocks, line_threshold)


def _assemble_line_with_gaps(blocks: List["OCRBlock"]) -> str:
    """
    Assemble a single line of blocks, inserting spaces based on gaps.
    """
    if not blocks:
        return ""
    
    if len(blocks) == 1:
        return blocks[0].text
    
    # Sort by X position
    sorted_blocks = sorted(blocks, key=lambda b: b.bounding_rect[0])
    
    # Calculate average character width for gap detection
    total_width = 0
    total_chars = 0
    for block in sorted_blocks:
        rect = block.bounding_rect
        width = rect[2] - rect[0]
        if block.text:
            total_width += width
            total_chars += len(block.text)
    
    avg_char_width = total_width / total_chars if total_chars > 0 else 10
    space_threshold = avg_char_width * 0.5  # Gap > 0.5 char width = space
    
    # Build line text
    parts = []
    prev_x_right = None
    
    for block in sorted_blocks:
        rect = block.bounding_rect
        x_left = rect[0]
        x_right = rect[2]
        
        if prev_x_right is not None:
            gap = x_left - prev_x_right
            if gap > space_threshold:
                # Add space
                parts.append(' ')
        
        parts.append(block.text)
        prev_x_right = x_right
    
    return ''.join(parts)


class EnhancedOCRProcessor:
    """
    Enhanced OCR processor with layout awareness.
    
    Combines OCR results with document layout analysis to produce
    better text extraction, especially for structured documents.
    """
    
    def __init__(
        self,
        layout_detector: Optional["DocumentLayoutDetector"] = None,
    ):
        """
        Initialize processor.
        
        Args:
            layout_detector: Optional document layout detector
        """
        self.layout_detector = layout_detector
    
    def process(
        self,
        image: np.ndarray,
        ocr_result: "OCRResult",
        apply_document_cleaning: bool = True,
    ) -> EnhancedOCRResult:
        """
        Process OCR result with layout enhancement and document template detection.
        
        Args:
            image: Original image (for layout analysis)
            ocr_result: OCR result with blocks
            apply_document_cleaning: Whether to apply document-specific cleaning
            
        Returns:
            EnhancedOCRResult with processed text, document type, and PHI fields
        """
        enhancements = []
        layout_result = None
        phi_fields = None
        
        # Calculate aspect ratio for document detection
        aspect_ratio = None
        if image is not None and len(image.shape) >= 2:
            h, w = image.shape[:2]
            aspect_ratio = w / h if h > 0 else None
        
        # Run layout analysis if available
        if self.layout_detector and self.layout_detector.is_initialized:
            try:
                layout_result = self.layout_detector.analyze(image)
                enhancements.append(f"layout({len(layout_result.regions)})")
            except Exception as e:
                logger.warning(f"Layout analysis failed: {e}")
        
        # Detect document type
        doc_type, doc_confidence = detect_document_type(
            ocr_result.full_text, 
            aspect_ratio
        )
        enhancements.append(f"type({doc_type.name})")
        
        is_id = doc_type in ID_CARD_TYPES and doc_confidence >= 0.3
        
        # Improve spacing with layout
        if layout_result and layout_result.regions:
            enhanced_text = improve_spacing_with_layout(
                ocr_result.blocks,
                layout_result.regions
            )
            enhancements.append("layout_spacing")
        else:
            enhanced_text = _basic_spatial_grouping(ocr_result.blocks)
            enhancements.append("basic_spacing")
        
        # Apply document-specific processing
        if apply_document_cleaning and doc_type != DocumentType.UNKNOWN:
            # Parse to extract PHI fields
            parse_result = parse_document(enhanced_text, doc_type, aspect_ratio)
            
            # Extract PHI fields for metadata
            phi_fields = {
                name: {
                    'value': field.value,
                    'phi_category': field.phi_category.value if field.phi_category else None,
                    'confidence': field.confidence,
                    'validated': field.validated,
                }
                for name, field in parse_result.get_phi_fields().items()
            }
            
            if phi_fields:
                enhancements.append(f"phi({len(phi_fields)})")
            
            # Clean field labels from text using the parser directly
            parser = get_parser(doc_type)
            if parser:
                enhanced_text = parser.clean_text(enhanced_text)
                enhancements.append("cleaned")
        
        return EnhancedOCRResult(
            raw_text=ocr_result.full_text,
            enhanced_text=enhanced_text,
            document_type=doc_type,
            is_id_card=is_id,
            layout_regions=len(layout_result.regions) if layout_result else 0,
            enhancements_applied=enhancements,
            phi_fields=phi_fields,
        )
