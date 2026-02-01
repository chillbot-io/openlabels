"""
Layout-aware OCR post-processing for structured documents.

.. deprecated::
    This module is DEPRECATED in favor of the more comprehensive:
    - document_templates.py: Full document parsers with HIPAA PHI categorization
    - enhanced_ocr.py: EnhancedOCRProcessor orchestrating document intelligence
    
    The functionality here has been superseded by those modules which provide:
    - 10+ document type parsers (DL, insurance, Medicare, passport, CMS-1500, etc.)
    - Field-level PHI extraction with HIPAA Safe Harbor categories
    - Validation (checksums, format verification)
    - Better OCR cleanup and spacing
    
    This module is kept for backwards compatibility but should not be used
    for new development. Use EnhancedOCRProcessor instead.

Handles driver's licenses, insurance cards, and other form-style documents
where field labels and values have spatial relationships.

The core problem: OCR returns flat text, losing the visual structure that
tells us "DLN:" is a label and "99999999" is its value.

This module uses bounding box coordinates to:
1. Group horizontally-adjacent text as label:value pairs
2. Clean up field codes (4d, 4b, 3DOB → DOB)
3. Fix common OCR artifacts in structured docs
"""

import logging
import re
import warnings
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .ocr import OCRBlock, OCRResult

logger = logging.getLogger(__name__)

# Emit deprecation warning on import
warnings.warn(
    "scrubiq.files.layout is deprecated. "
    "Use enhanced_ocr.EnhancedOCRProcessor instead.",
    DeprecationWarning,
    stacklevel=2
)


# --- DOCUMENT TYPE DETECTION ---
def detect_document_type(ocr_result: OCRResult) -> str:
    """
    Classify document type based on OCR content.
    
    Returns:
        One of: 'drivers_license', 'insurance_card', 'lab_report', 
                'clinical_note', 'unknown'
    """
    text = ocr_result.full_text.upper()
    
    # Driver's License indicators
    dl_keywords = ['DRIVER', 'LICENSE', 'DLN', 'DOB:', 'EXP:', 'CLASS:', 'OPER', 'DMV']
    dl_score = sum(1 for k in dl_keywords if k in text)
    
    # Insurance Card indicators  
    ins_keywords = ['MEMBER', 'GROUP', 'COPAY', 'SUBSCRIBER', 'PAYER', 'RX BIN', 'INSURANCE', 'HEALTH PLAN']
    ins_score = sum(1 for k in ins_keywords if k in text)
    
    # Lab Report indicators
    lab_keywords = ['SPECIMEN', 'REFERENCE RANGE', 'RESULT', 'COLLECTED', 'FASTING', 'LABORATORY', 'ABNORMAL']
    lab_score = sum(1 for k in lab_keywords if k in text)
    
    # Clinical Note indicators
    clinical_keywords = ['PATIENT', 'DIAGNOSIS', 'ASSESSMENT', 'CHIEF COMPLAINT', 'HPI', 'VITALS', 'SUBJECTIVE']
    clinical_score = sum(1 for k in clinical_keywords if k in text)
    
    scores = {
        'drivers_license': dl_score,
        'insurance_card': ins_score,
        'lab_report': lab_score,
        'clinical_note': clinical_score,
    }
    
    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]
    
    if best_score >= 2:
        logger.debug(f"Detected document type: {best_type} (score={best_score})")
        return best_type
    
    return 'unknown'


# --- FIELD CODE CLEANUP ---
# PA Driver's License field codes
PA_FIELD_CODES = {
    '1': 'FAMILY_NAME',
    '2': 'GIVEN_NAME', 
    '3': 'DOB',
    '4a': 'ISSUE_DATE',
    '4b': 'EXPIRY_DATE',
    '4d': 'DLN',
    '5': 'DOCUMENT_DISCRIMINATOR',
    '8': 'ADDRESS',
    '9': 'CLASS',
    '9a': 'ENDORSEMENTS',
    '12': 'RESTRICTIONS',
    '15': 'SEX',
    '16': 'HEIGHT',
    '17': 'WEIGHT',
    '18': 'EYES',
}

# Common field code patterns across states
FIELD_CODE_PATTERN = re.compile(
    r'\b(\d{1,2}[a-zA-Z]?)(?=[A-Z]{2,}:|\s*[A-Z]{2,}:)',
    re.IGNORECASE
)


def clean_field_codes(text: str) -> str:
    """
    Remove field code prefixes from driver's license text.
    
    "4dDLN:99999999" → "DLN:99999999"
    "3DOB: 01/07/1973" → "DOB: 01/07/1973"
    """
    # Remove numeric prefixes before labels
    cleaned = FIELD_CODE_PATTERN.sub('', text)
    return cleaned


def clean_ocr_artifacts(text: str, doc_type: str = 'unknown') -> str:
    """
    Fix common OCR artifacts based on document type.
    """
    # Add space between numbers and uppercase words (8123MAINSTREET → 8123 MAINSTREET)
    text = re.sub(r'(\d)([A-Z]{3,})', r'\1 \2', text)
    
    # Fix stuck colons (:99999999 → 99999999)
    text = re.sub(r'^:', '', text)
    text = re.sub(r'\s:', ' ', text)
    
    if doc_type == 'drivers_license':
        # Fix common DL misreads
        text = re.sub(r'\bDUPS?:?\s*00\b', '', text)  # Remove "DUPS:00"
        text = re.sub(r'\bORGAN\s*DONOR\b', '', text, flags=re.IGNORECASE)  # Remove organ donor text
        
    return text.strip()


# --- LAYOUT GROUPING ---
@dataclass
class LayoutField:
    """A label:value pair extracted from layout analysis."""
    label: str
    value: str
    confidence: float
    label_bbox: List[List[float]]
    value_bbox: Optional[List[List[float]]] = None


def get_block_center_y(block: OCRBlock) -> float:
    """Get vertical center of block."""
    ys = [p[1] for p in block.bbox]
    return (min(ys) + max(ys)) / 2


def get_block_left_x(block: OCRBlock) -> float:
    """Get left edge of block."""
    return min(p[0] for p in block.bbox)


def get_block_right_x(block: OCRBlock) -> float:
    """Get right edge of block."""
    return max(p[0] for p in block.bbox)


def blocks_on_same_line(block1: OCRBlock, block2: OCRBlock, tolerance: float = 15) -> bool:
    """Check if two blocks are on the same horizontal line."""
    center1 = get_block_center_y(block1)
    center2 = get_block_center_y(block2)
    return abs(center1 - center2) < tolerance


def block_is_to_right(label_block: OCRBlock, value_block: OCRBlock, max_gap: float = 100) -> bool:
    """Check if value_block is to the right of label_block within reasonable distance."""
    label_right = get_block_right_x(label_block)
    value_left = get_block_left_x(value_block)
    
    # Value should be to the right, with reasonable gap
    gap = value_left - label_right
    return 0 < gap < max_gap


def is_label_block(block: OCRBlock) -> bool:
    """Check if block looks like a field label."""
    text = block.text.strip()
    
    # Ends with colon
    if text.endswith(':'):
        return True
    
    # Known label patterns
    label_patterns = [
        r'^(DLN|DOB|EXP|ISS|SEX|HGT|WGT|EYES|CLASS|NAME|ADDR|MEMBER|GROUP|ID)$',
        r'^[A-Z]{2,}:?$',  # All caps, 2+ chars
    ]
    
    for pattern in label_patterns:
        if re.match(pattern, text, re.IGNORECASE):
            return True
    
    return False


def extract_fields_by_layout(ocr_result: OCRResult) -> List[LayoutField]:
    """
    Group OCR blocks into label:value pairs based on spatial layout.
    
    Algorithm:
    1. Find blocks that look like labels (end with ":" or match patterns)
    2. For each label, find blocks to its right on the same line
    3. Those become the value
    """
    if not ocr_result.blocks:
        return []
    
    fields = []
    used_indices = set()
    
    # Sort blocks by position (top-to-bottom, left-to-right)
    sorted_blocks = sorted(
        enumerate(ocr_result.blocks),
        key=lambda x: (get_block_center_y(x[1]), get_block_left_x(x[1]))
    )
    
    for idx, block in sorted_blocks:
        if idx in used_indices:
            continue
            
        if is_label_block(block):
            label_text = block.text.strip().rstrip(':')
            used_indices.add(idx)
            
            # Find value blocks to the right on same line
            value_parts = []
            value_bboxes = []
            
            for other_idx, other_block in sorted_blocks:
                if other_idx in used_indices:
                    continue
                if other_idx == idx:
                    continue
                    
                if (blocks_on_same_line(block, other_block) and 
                    block_is_to_right(block, other_block)):
                    value_parts.append(other_block.text)
                    value_bboxes.append(other_block.bbox)
                    used_indices.add(other_idx)
            
            if value_parts:
                value_text = ' '.join(value_parts)
                fields.append(LayoutField(
                    label=label_text,
                    value=value_text,
                    confidence=block.confidence,
                    label_bbox=block.bbox,
                    value_bbox=value_bboxes[0] if value_bboxes else None,
                ))
    
    return fields


# --- MAIN PROCESSING ---
def process_structured_document(ocr_result: OCRResult) -> OCRResult:
    """
    Apply layout-aware processing to OCR result.
    
    For structured documents (IDs, cards), this:
    1. Detects document type
    2. Extracts label:value pairs by layout
    3. Cleans field codes and artifacts
    4. Rebuilds clean text
    
    For unstructured documents, returns original with minor cleanup.
    """
    if not ocr_result.blocks:
        return ocr_result
    
    doc_type = detect_document_type(ocr_result)
    logger.info(f"Document type: {doc_type}")
    
    if doc_type in ('drivers_license', 'insurance_card'):
        return _process_id_document(ocr_result, doc_type)
    else:
        # For other doc types, just clean up the text
        return _apply_basic_cleanup(ocr_result, doc_type)


def _process_id_document(ocr_result: OCRResult, doc_type: str) -> OCRResult:
    """Process ID-style documents with layout grouping."""
    
    # Extract fields by layout
    fields = extract_fields_by_layout(ocr_result)
    
    if fields:
        logger.info(f"Extracted {len(fields)} fields by layout")
        for f in fields:
            logger.debug(f"  {f.label}: {f.value}")
    
    # Build clean text from fields
    # Also keep non-field blocks for complete text
    field_texts = []
    for f in fields:
        clean_label = clean_field_codes(f.label)
        clean_value = clean_ocr_artifacts(f.value, doc_type)
        field_texts.append(f"{clean_label}: {clean_value}")
    
    # Also include blocks that weren't part of label:value pairs
    # (like the header "DRIVER'S LICENSE" or name without label)
    used_texts = set()
    for f in fields:
        used_texts.add(f.label.lower())
        used_texts.add(f.value.lower())
    
    other_texts = []
    for block in ocr_result.blocks:
        if block.text.lower().strip() not in used_texts:
            cleaned = clean_ocr_artifacts(clean_field_codes(block.text), doc_type)
            if cleaned and len(cleaned) > 1:
                other_texts.append(cleaned)
    
    # Combine: fields first (structured), then other text
    all_parts = field_texts + other_texts
    new_text = '\n'.join(all_parts)
    
    # Rebuild offset map for the new text
    new_blocks = []
    new_offset_map = []
    current_offset = 0
    
    # This is simplified - proper implementation would track exact positions
    for i, block in enumerate(ocr_result.blocks):
        cleaned_text = clean_ocr_artifacts(clean_field_codes(block.text), doc_type)
        new_blocks.append(OCRBlock(
            text=cleaned_text,
            bbox=block.bbox,
            confidence=block.confidence,
        ))
        
        start = current_offset
        end = current_offset + len(cleaned_text)
        new_offset_map.append((start, end, i))
        current_offset = end + 1  # +1 for separator
    
    return OCRResult(
        full_text=new_text,
        blocks=new_blocks,
        offset_map=new_offset_map,
        confidence=ocr_result.confidence,
    )


def _apply_basic_cleanup(ocr_result: OCRResult, doc_type: str) -> OCRResult:
    """Apply basic cleanup without layout restructuring."""
    
    # Clean each block's text
    new_blocks = []
    for block in ocr_result.blocks:
        cleaned = clean_ocr_artifacts(block.text, doc_type)
        new_blocks.append(OCRBlock(
            text=cleaned,
            bbox=block.bbox,
            confidence=block.confidence,
        ))
    
    # Rebuild full text
    new_text = '\n'.join(b.text for b in new_blocks)
    
    return OCRResult(
        full_text=new_text,
        blocks=new_blocks,
        offset_map=ocr_result.offset_map,
        confidence=ocr_result.confidence,
    )


# --- FIELD-BASED PHI TAGGING (for structured docs) ---
# Fields that are always PHI on driver's licenses
DL_PHI_FIELDS = {
    'DLN', 'DOB', 'NAME', 'GIVEN_NAME', 'FAMILY_NAME', 'ADDRESS', 
    'EXP', 'ISS', 'ISSUE_DATE', 'EXPIRY_DATE', 'DOCUMENT_DISCRIMINATOR',
}

# Fields that might be PHI on insurance cards
INSURANCE_PHI_FIELDS = {
    'MEMBER', 'MEMBER ID', 'SUBSCRIBER', 'GROUP', 'NAME', 'DOB', 'ID',
}


def get_phi_fields_for_doc_type(doc_type: str) -> set:
    """Get set of field names that are PHI for this document type."""
    if doc_type == 'drivers_license':
        return DL_PHI_FIELDS
    elif doc_type == 'insurance_card':
        return INSURANCE_PHI_FIELDS
    return set()
