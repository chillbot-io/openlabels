"""
File processor orchestrating extraction → metadata stripping → face detection → OCR → PHI detection.

Coordinates all file processing stages and updates job status.

Processing Order (Critical for Security):
1. Validate file type and size
2. Strip ALL metadata (including thumbnails that may contain unredacted faces)
3. Detect and redact faces (for images/scanned PDFs)
4. Extract text (with OCR if needed)
5. Run PHI detection on text
6. Redact PHI in images (burn black boxes over detected regions)
7. Store results (encrypted images + text)

The order matters:
- Metadata must be stripped BEFORE face detection because EXIF thumbnails
  may contain the original unredacted image
- Face redaction must happen BEFORE OCR so any text in face regions is also removed
- PHI text redaction happens AFTER OCR so we have bounding boxes to target
"""

import io
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Optional, Dict, Any, TYPE_CHECKING

from .ocr import OCREngine, OCRResult
from .extractor import (
    BaseExtractor,
    PDFExtractor,
    DOCXExtractor,
    XLSXExtractor,
    ImageExtractor,
    TextExtractor,
    RTFExtractor,
    ExtractionResult,
)
from .validators import infer_content_type
from .jobs import FileJob, JobStatus, JobManager
from .temp_storage import SecureTempDir
from ..constants import MAX_DOCUMENT_PAGES, MODEL_LOAD_TIMEOUT

if TYPE_CHECKING:
    from ..core import ScrubIQ
    from ..types import Span
    from ..storage import ImageStore

logger = logging.getLogger(__name__)


# Image MIME types that should have face detection applied
IMAGE_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/tiff',
    'image/webp',
    'image/gif',
    'image/bmp',
}

# MIME types that can produce visual redaction output
VISUAL_REDACTION_MIME_TYPES = IMAGE_MIME_TYPES | {'application/pdf'}


# Mapping from document_templates PHICategory to Span entity_type
PHI_CATEGORY_TO_ENTITY_TYPE = {
    'name': 'NAME',
    'address': 'ADDRESS',
    'date': 'DATE',
    'phone': 'PHONE',
    'fax': 'FAX',
    'email': 'EMAIL',
    'ssn': 'SSN',
    'mrn': 'MRN',
    'health_plan_id': 'HEALTH_PLAN_ID',
    'account_number': 'ACCOUNT_NUMBER',
    'license_number': 'DRIVER_LICENSE',
    'vehicle_id': 'VIN',
    'device_id': 'DEVICE_ID',
    'url': 'URL',
    'ip_address': 'IP_ADDRESS',
    'biometric': 'BIOMETRIC_ID',
    'photo': 'PHOTO_ID',
    'other_unique_id': 'UNIQUE_ID',
}


def phi_fields_to_spans(
    text: str, 
    phi_fields: Dict[str, Any],
    detector_name: str = "document_template"
) -> List["Span"]:
    """
    Convert pre-extracted PHI fields to Span objects by finding them in text.
    
    This enables document-aware PHI detection to feed directly into the
    detection pipeline as high-confidence, pre-validated spans.
    
    Args:
        text: The text to search for PHI values
        phi_fields: Dict from EnhancedOCRProcessor with structure:
            {field_name: {value, phi_category, confidence, validated}}
        detector_name: Name to use for detector attribution
        
    Returns:
        List of Span objects for detected PHI values
    """
    from ..types import Span, Tier
    
    if not phi_fields or not text:
        return []
    
    spans = []
    
    for field_name, field_data in phi_fields.items():
        value = field_data.get('value')
        phi_category = field_data.get('phi_category')
        confidence = field_data.get('confidence', 0.9)
        validated = field_data.get('validated', False)
        
        if not value or not phi_category:
            continue
        
        # Map PHI category to entity type
        entity_type = PHI_CATEGORY_TO_ENTITY_TYPE.get(phi_category, 'UNIQUE_ID')
        
        # Boost confidence if field was validated (checksum, format check, etc.)
        if validated:
            confidence = min(1.0, confidence + 0.1)
        
        # Find all occurrences of this value in the text
        # Use word boundaries to avoid partial matches
        try:
            # Escape special regex characters in value
            escaped_value = re.escape(value)
            pattern = rf'\b{escaped_value}\b'
            
            for match in re.finditer(pattern, text, re.IGNORECASE):
                # Create span with STRUCTURED tier (high authority)
                span = Span(
                    start=match.start(),
                    end=match.end(),
                    text=match.group(),
                    entity_type=entity_type,
                    confidence=confidence,
                    detector=f"{detector_name}:{field_name}",
                    tier=Tier.STRUCTURED,  # High authority - from document parsing
                )
                spans.append(span)
                
                logger.debug(
                    f"PHI field '{field_name}' ({phi_category}) found at "
                    f"{match.start()}-{match.end()}: {entity_type}"
                )
                
        except re.error as e:
            logger.warning(f"Regex error for PHI field '{field_name}': {e}")
            continue
    
    logger.info(f"Converted {len(spans)} PHI fields to spans from document parsing")
    return spans


class FileProcessor:
    """
    Orchestrates file processing pipeline.
    
    Flow:
    1. Validate file
    2. Create job
    3. Wait for models (if still loading)
    4. Strip metadata (all files)
    5. Detect/redact faces (images and scanned PDFs)
    6. Extract text (with OCR if needed)
    7. Run PHI detection
    8. Redact PHI in images (burn black boxes)
    9. Store encrypted images + text results
    
    Processing runs in a thread pool to avoid blocking.
    Models are loaded lazily in background to not block startup.
    """
    
    def __init__(
        self,
        scrubiq: "ScrubIQ",
        ocr_engine: Optional[OCREngine] = None,
        max_workers: int = 1,  # One job at a time for multi-page support
        enable_face_detection: bool = True,
        enable_signature_detection: bool = True,
        enable_metadata_stripping: bool = True,
        enable_image_redaction: bool = True,
        face_redaction_method: str = "blur",
    ):
        """
        Initialize file processor.
        
        Args:
            scrubiq: Main CR instance for PHI detection
            ocr_engine: OCR engine (created if not provided)
            max_workers: Max concurrent file processing tasks (default 1 for multi-page)
            enable_face_detection: Whether to detect and redact faces
            enable_signature_detection: Whether to detect and redact signatures
            enable_metadata_stripping: Whether to strip file metadata
            enable_image_redaction: Whether to burn PHI redactions into images
            face_redaction_method: "blur", "pixelate", or "fill"
        """
        self.cr = scrubiq
        self.job_manager = JobManager()
        
        # Feature flags
        self.enable_face_detection = enable_face_detection
        self.enable_signature_detection = enable_signature_detection
        self.enable_metadata_stripping = enable_metadata_stripping
        self.enable_image_redaction = enable_image_redaction
        self.face_redaction_method = face_redaction_method
        
        # OCR engine
        if ocr_engine:
            self.ocr_engine = ocr_engine
        else:
            self.ocr_engine = OCREngine(scrubiq.config.models_dir)
        
        # Metadata stripper (lazy loaded)
        self._metadata_stripper = None
        
        # Face protector (lazy loaded)
        self._face_protector = None
        
        # Signature protector (lazy loaded)
        self._signature_protector = None
        
        # Image store (lazy loaded - requires unlocked vault)
        self._image_store = None
        
        # Thread pool for background processing
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Note: Extractors are created per-job with temp_dir
        # These are the default extractors without temp support
        self._default_extractors: List[BaseExtractor] = [
            PDFExtractor(self.ocr_engine),
            DOCXExtractor(),
            XLSXExtractor(),
            ImageExtractor(self.ocr_engine),
            TextExtractor(),
            RTFExtractor(),
        ]
    
    def _create_extractors(self, temp_dir: Optional[SecureTempDir] = None) -> List[BaseExtractor]:
        """
        Create extractors with optional temp directory for page storage.
        
        Args:
            temp_dir: Secure temp directory for multi-page processing
            
        Returns:
            List of extractors
        """
        return [
            PDFExtractor(self.ocr_engine, temp_dir=temp_dir),
            DOCXExtractor(),
            XLSXExtractor(),
            ImageExtractor(self.ocr_engine, temp_dir=temp_dir),
            TextExtractor(),
            RTFExtractor(),
        ]
    
    def start_model_loading(self) -> None:
        """
        Start loading models in background.
        
        Call after unlock to begin lazy loading of OCR and face detection models.
        Jobs will wait for models with LOADING_MODELS status if not ready.
        """
        # Start OCR loading
        if self.ocr_engine.is_available and not self.ocr_engine.is_initialized:
            self.ocr_engine.start_loading()
            logger.info("Started OCR model loading in background")
        
        # Start face detection loading
        if self.enable_face_detection:
            # Access property to trigger lazy load
            fp = self.face_protector
            if fp and not fp.is_initialized:
                fp.start_loading()
                logger.info("Started face detection model loading in background")
    
    def await_models_ready(self, timeout: float = MODEL_LOAD_TIMEOUT) -> bool:
        """
        Wait for all models to be ready.
        
        Args:
            timeout: Maximum seconds to wait
            
        Returns:
            True if all models ready, False if timeout
        """
        all_ready = True
        
        # Wait for OCR
        if self.ocr_engine.is_available:
            if not self.ocr_engine.await_ready(timeout=timeout):
                logger.warning("OCR model load timeout")
                all_ready = False
        
        # Wait for face detection
        if self.enable_face_detection and self.face_protector:
            if not self.face_protector.await_ready(timeout=timeout):
                logger.warning("Face detection model load timeout")
                all_ready = False
        
        return all_ready
    
    @property
    def models_ready(self) -> bool:
        """Check if all required models are loaded."""
        # OCR must be ready for image/PDF processing
        if self.ocr_engine.is_available and not self.ocr_engine.is_initialized:
            return False
        
        # Face detection must be ready if enabled
        if self.enable_face_detection:
            if self._face_protector and not self._face_protector.is_initialized:
                return False
        
        return True
    
    @property
    def metadata_stripper(self):
        """Lazy load metadata stripper."""
        if self._metadata_stripper is None and self.enable_metadata_stripping:
            try:
                from ..image_protection import MetadataStripper
                self._metadata_stripper = MetadataStripper()
                logger.info("Metadata stripper initialized")
            except ImportError as e:
                logger.warning(f"Metadata stripping unavailable: {e}")
                self.enable_metadata_stripping = False
        return self._metadata_stripper
    
    @property
    def face_protector(self):
        """Lazy load face protector."""
        if self._face_protector is None and self.enable_face_detection:
            try:
                from ..image_protection import FaceProtector
                self._face_protector = FaceProtector(
                    models_dir=self.cr.config.models_dir,
                    method=self.face_redaction_method,
                )
                if not self._face_protector.is_available:
                    logger.warning("Face detection models not found, feature disabled")
                    self.enable_face_detection = False
                    self._face_protector = None
                else:
                    logger.info("Face protector initialized")
            except ImportError as e:
                logger.warning(f"Face detection unavailable: {e}")
                self.enable_face_detection = False
        return self._face_protector
    
    @property
    def signature_protector(self):
        """Lazy load signature protector."""
        if self._signature_protector is None and self.enable_signature_detection:
            try:
                from ..image_protection import SignatureProtector
                self._signature_protector = SignatureProtector(
                    models_dir=self.cr.config.models_dir,
                )
                if not self._signature_protector.is_available:
                    logger.warning("Signature detection model not found, feature disabled")
                    self.enable_signature_detection = False
                    self._signature_protector = None
                else:
                    logger.info("Signature protector initialized")
            except ImportError as e:
                logger.warning(f"Signature detection unavailable: {e}")
                self.enable_signature_detection = False
        return self._signature_protector
    
    @property
    def image_store(self) -> Optional["ImageStore"]:
        """Lazy load image store (requires unlocked vault)."""
        if self._image_store is None and self.enable_image_redaction:
            if not self.cr.is_unlocked:
                logger.debug("Image store not available - vault locked")
                return None
            try:
                from ..storage import ImageStore
                images_dir = self.cr.config.data_dir / "images"
                self._image_store = ImageStore(
                    db=self.cr._db,
                    keys=self.cr._keys,
                    images_dir=images_dir,
                    session_id=self.cr._session_id,
                )
                logger.info(f"Image store initialized at {images_dir}")
            except Exception as e:
                logger.warning(f"Image store unavailable: {e}")
                self.enable_image_redaction = False
        return self._image_store
    
    def _redact_image_phi(
        self,
        image_bytes: bytes,
        ocr_result: OCRResult,
        phi_spans: List["Span"],
        padding: int = 2,
    ) -> bytes:
        """
        Draw black rectangles over PHI regions in image.
        
        Args:
            image_bytes: Image bytes (already face-blurred)
            ocr_result: OCR result with bounding boxes
            phi_spans: Detected PHI spans from pipeline
            padding: Pixels to add around redaction boxes
            
        Returns:
            Redacted image as PNG bytes
        """
        from PIL import Image, ImageDraw
        
        # Load image
        img = Image.open(io.BytesIO(image_bytes))
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        draw = ImageDraw.Draw(img)
        redacted_count = 0
        
        # For each PHI span, find overlapping OCR blocks and redact
        for span in phi_spans:
            blocks = ocr_result.get_blocks_for_span(span.start, span.end)
            for block in blocks:
                rect = block.bounding_rect
                # Add padding around the redaction box
                padded_rect = (
                    max(0, rect[0] - padding),
                    max(0, rect[1] - padding),
                    min(img.width, rect[2] + padding),
                    min(img.height, rect[3] + padding),
                )
                draw.rectangle(padded_rect, fill="black")
                redacted_count += 1
        
        logger.debug(f"Drew {redacted_count} redaction boxes for {len(phi_spans)} PHI spans")
        
        # Save as PNG to avoid JPEG artifacts on redaction boxes
        output = io.BytesIO()
        img.save(output, format='PNG')
        return output.getvalue()
    
    def _images_to_pdf(self, images: List[bytes], output_path: Path) -> None:
        """
        Convert multiple images to a single PDF.
        
        Used for multi-page TIFF output where we want a single
        downloadable file with all pages redacted.
        
        Args:
            images: List of PNG image bytes (one per page)
            output_path: Where to write the PDF
        """
        import fitz  # PyMuPDF
        
        doc = fitz.open()
        
        for img_bytes in images:
            # Create page from image
            img_doc = fitz.open(stream=img_bytes, filetype="png")
            rect = img_doc[0].rect
            
            # Create page with same dimensions
            page = doc.new_page(width=rect.width, height=rect.height)
            page.insert_image(rect, stream=img_bytes)
            img_doc.close()
        
        doc.save(str(output_path))
        doc.close()
        
        logger.debug(f"Created PDF with {len(images)} pages at {output_path}")
    
    def get_extractor(
        self, 
        content_type: str, 
        filename: str,
    ) -> Optional[BaseExtractor]:
        """
        Get appropriate extractor for file type.
        
        Args:
            content_type: MIME type
            filename: Filename (for extension detection)
            
        Returns:
            Matching extractor, or None if unsupported
        """
        ext = Path(filename).suffix.lower()
        
        for extractor in self._default_extractors:
            if extractor.can_handle(content_type, ext):
                return extractor

        return None

    def _create_file_job(
        self,
        content: bytes,
        filename: str,
        content_type: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> FileJob:
        """
        Create a FileJob with common setup logic.

        DRY helper for process_file and process_file_async.

        Args:
            content: File bytes
            filename: Original filename
            content_type: MIME type (inferred if not provided)
            conversation_id: Optional conversation to link to

        Returns:
            Initialized FileJob ready for processing
        """
        # Infer content type if needed
        if not content_type:
            content_type = infer_content_type(filename) or "application/octet-stream"

        # Create and return job
        return self.job_manager.create_job(
            filename=filename,
            content_type=content_type,
            size_bytes=len(content),
            conversation_id=conversation_id,
        )

    def process_file(
        self,
        content: bytes,
        filename: str,
        content_type: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> FileJob:
        """
        Process a file synchronously.

        For async processing, use process_file_async.

        Args:
            content: File bytes
            filename: Original filename
            content_type: MIME type (inferred if not provided)
            conversation_id: Optional conversation to link to

        Returns:
            Completed FileJob with results
        """
        job = self._create_file_job(content, filename, content_type, conversation_id)
        self._process_job(job, content)
        return job

    def process_file_async(
        self,
        content: bytes,
        filename: str,
        content_type: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> FileJob:
        """
        Start async file processing.

        Returns immediately with job ID. Poll job status for updates.

        Args:
            content: File bytes
            filename: Original filename
            content_type: MIME type (inferred if not provided)
            conversation_id: Optional conversation to link to

        Returns:
            FileJob (check status for progress)
        """
        job = self._create_file_job(content, filename, content_type, conversation_id)
        self._executor.submit(self._process_job, job, content)
        return job

    def _detect_and_redact_image_feature(
        self,
        content: bytes,
        job: FileJob,
        protector,
        feature_name: str,
        metadata_key: str,
        progress: float,
    ) -> bytes:
        """
        Detect and redact a feature (faces/signatures) from image bytes.

        Args:
            content: Image bytes
            job: Job for status updates
            protector: Face or signature protector instance
            feature_name: "faces" or "signatures" for logging
            metadata_key: Key to store result in job.metadata
            progress: Progress value (0-1) for status update

        Returns:
            Possibly-modified image bytes
        """
        self.job_manager.update_job(
            job.id,
            status=JobStatus.PROCESSING,
            progress=progress,
            status_message=f"Detecting {feature_name}...",
        )

        try:
            import numpy as np
            from PIL import Image

            # Load image
            img = Image.open(io.BytesIO(content))

            # Convert to RGB mode - required for detection
            if img.mode != 'RGB':
                logger.debug(f"Converting image from {img.mode} to RGB for {feature_name} detection")
                img = img.convert('RGB')

            img_array = np.array(img)

            # Detect and redact
            result, redacted_array = protector.process(img_array)

            if result.redaction_applied:
                # Save back to bytes
                redacted_img = Image.fromarray(redacted_array)
                output = io.BytesIO()

                # Determine format
                fmt = 'JPEG' if job.content_type == 'image/jpeg' else 'PNG'
                if fmt == 'JPEG':
                    redacted_img.save(output, format=fmt, quality=95)
                else:
                    redacted_img.save(output, format=fmt)

                content = output.getvalue()

                # Get count from result (works for both face and signature results)
                count = getattr(result, 'faces_detected', None) or getattr(result, 'signatures_detected', 0)
                logger.info(f"Redacted {count} {feature_name} in {job.filename}")

            # Store detection result
            if hasattr(job, 'metadata'):
                job.metadata[metadata_key] = result.to_audit_dict()

        except Exception as e:
            logger.error(f"{feature_name.capitalize()} detection failed: {e}")
            # Continue processing - detection failure shouldn't block

        return content

    def _apply_visual_redaction(
        self,
        job: FileJob,
        content: bytes,
        extraction: ExtractionResult,
        detection_spans: List["Span"],
        is_image: bool,
    ) -> bool:
        """
        Apply visual redaction (face blur + PHI boxes) to scanned pages.

        Returns:
            True if redacted image was stored, False otherwise
        """
        from ..storage import ImageFileType
        from ..types import AuditEventType, Span
        from PIL import Image
        import numpy as np

        redacted_pages = []
        page_text_offset = 0

        scanned_pages = [p for p in extraction.page_infos if p.is_scanned]

        for page_info in scanned_pages:
            page_idx = page_info.page_num

            # Get page image bytes
            if page_info.temp_image_path:
                page_bytes = Path(page_info.temp_image_path).read_bytes()
            elif is_image and page_idx == 0:
                page_bytes = content
            else:
                logger.warning(f"No image available for page {page_idx}")
                continue

            # Apply face detection for PDF pages (images already processed)
            if not is_image and self.enable_face_detection and self.face_protector:
                try:
                    img = Image.open(io.BytesIO(page_bytes))
                    if img.mode != 'RGB':
                        img = img.convert('RGB')
                    img_array = np.array(img)

                    face_result, redacted_array = self.face_protector.process(img_array)

                    if face_result.redaction_applied:
                        redacted_img = Image.fromarray(redacted_array)
                        output_buffer = io.BytesIO()
                        redacted_img.save(output_buffer, format='PNG')
                        page_bytes = output_buffer.getvalue()
                        logger.debug(f"Page {page_idx}: blurred {face_result.faces_detected} faces")
                except Exception as e:
                    logger.warning(f"Face detection failed for page {page_idx}: {e}")

            # Find PHI spans for this page and apply text redaction
            if page_info.ocr_result and page_info.ocr_result.full_text:
                page_text_len = len(page_info.ocr_result.full_text)
                page_spans = [
                    s for s in detection_spans
                    if page_text_offset <= s.start < page_text_offset + page_text_len
                ]

                # Adjust span offsets to be page-relative
                adjusted_spans = [
                    Span(
                        start=s.start - page_text_offset,
                        end=s.end - page_text_offset,
                        text=s.text,
                        entity_type=s.entity_type,
                        confidence=s.confidence,
                        detector=s.detector,
                        tier=s.tier,
                    )
                    for s in page_spans
                ]

                # Redact PHI on this page
                if adjusted_spans:
                    redacted_page = self._redact_image_phi(
                        page_bytes, page_info.ocr_result, adjusted_spans
                    )
                else:
                    redacted_page = page_bytes

                redacted_pages.append(redacted_page)
                page_text_offset += page_text_len + 2  # +2 for \n\n separator
            else:
                # No OCR text, but still store the (possibly face-blurred) image
                redacted_pages.append(page_bytes)

        if not redacted_pages:
            return False

        # Store results
        if len(redacted_pages) == 1 and is_image:
            self.image_store.store(
                job_id=job.id,
                file_type=ImageFileType.REDACTED,
                image_bytes=redacted_pages[0],
                original_filename=job.filename,
                content_type="image/png",
            )
        else:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
                tmp_path = Path(tmp.name)

            self._images_to_pdf(redacted_pages, tmp_path)
            pdf_bytes = tmp_path.read_bytes()
            tmp_path.unlink()

            self.image_store.store(
                job_id=job.id,
                file_type=ImageFileType.REDACTED_PDF,
                image_bytes=pdf_bytes,
                original_filename=job.filename.rsplit('.', 1)[0] + '.pdf',
                content_type="application/pdf",
            )

        # Log audit event
        regions = []
        for page_info in scanned_pages:
            if page_info.ocr_result:
                for span in detection_spans:
                    blocks = page_info.ocr_result.get_blocks_for_span(span.start, span.end)
                    for block in blocks:
                        regions.append({
                            "page": page_info.page_num,
                            "bbox": list(block.bounding_rect),
                            "entity_type": span.entity_type,
                        })

        self.cr._audit.log(AuditEventType.IMAGE_REDACTED, {
            "job_id": job.id,
            "filename": job.filename,
            "scanned_pages": len(scanned_pages),
            "phi_regions_count": len(regions),
            "regions": regions[:50],
        })

        logger.info(
            f"Redacted {len(detection_spans)} PHI regions "
            f"across {len(scanned_pages)} page(s) in {job.filename}"
        )

        return True

    def _process_job(self, job: FileJob, content: bytes) -> None:
        """
        Internal job processing.
        
        Updates job status as processing progresses.
        Handles multi-page documents with parallel page processing.
        """
        start_time = time.perf_counter()
        temp_dir = None
        
        try:
            # 0. Wait for models if still loading
            if not self.models_ready:
                self.job_manager.update_job(
                    job.id,
                    status=JobStatus.LOADING_MODELS,
                    progress=0.0,
                    status_message="Waiting for models to load...",
                )
                
                if not self.await_models_ready(timeout=MODEL_LOAD_TIMEOUT):
                    job.set_error("Model loading timeout")
                    return
            
            # 1. Find extractor
            extractor = self.get_extractor(job.content_type, job.filename)
            if not extractor:
                job.set_error(f"Unsupported file type: {job.content_type}")
                return
            
            # Check if this file type supports visual redaction
            supports_visual_redaction = job.content_type in VISUAL_REDACTION_MIME_TYPES
            
            # Create temp directory for multi-page processing
            if supports_visual_redaction and self.enable_image_redaction:
                temp_dir = SecureTempDir(job.id)
                temp_dir.create()
                
                # Create extractors with temp dir
                extractors = self._create_extractors(temp_dir)
                ext = Path(job.filename).suffix.lower()
                extractor = None
                for e in extractors:
                    if e.can_handle(job.content_type, ext):
                        extractor = e
                        break
                
                if not extractor:
                    job.set_error(f"Unsupported file type: {job.content_type}")
                    return
            
            # 2. Strip metadata FIRST (critical for security)
            if self.enable_metadata_stripping and self.metadata_stripper:
                self.job_manager.update_job(
                    job.id,
                    status=JobStatus.PROCESSING,
                    progress=0.05,
                    status_message="Stripping metadata...",
                )
                
                try:
                    content, meta_result = self.metadata_stripper.strip(content, job.filename)
                    
                    # Store metadata stripping result in job
                    if hasattr(job, 'metadata'):
                        job.metadata['metadata_stripped'] = meta_result.to_audit_dict()
                    
                    if meta_result.had_thumbnail:
                        logger.warning(
                            f"Stripped EXIF thumbnail from {job.filename} - "
                            "may have contained unredacted image"
                        )
                    
                    logger.info(
                        f"Stripped {meta_result.total_fields_removed} metadata fields "
                        f"from {job.filename}"
                    )
                except Exception as e:
                    logger.error(f"Metadata stripping failed: {e}")
                    # Continue processing - metadata stripping failure shouldn't block
            
            # 3. Face detection/redaction (for images only)
            is_image = job.content_type in IMAGE_MIME_TYPES
            image_features_redacted = False  # Track if faces/signatures were blurred

            if is_image and self.enable_face_detection and self.face_protector:
                content = self._detect_and_redact_image_feature(
                    content, job, self.face_protector,
                    feature_name="faces",
                    metadata_key="face_detection",
                    progress=0.15,
                )
                # Check if faces were actually redacted
                face_result = job.metadata.get("face_detection", {})
                if face_result.get("redaction_applied"):
                    image_features_redacted = True

            # 3b. Signature detection/redaction (for images only)
            if is_image and self.enable_signature_detection and self.signature_protector:
                content = self._detect_and_redact_image_feature(
                    content, job, self.signature_protector,
                    feature_name="signatures",
                    metadata_key="signature_detection",
                    progress=0.2,
                )
                # Check if signatures were actually redacted
                sig_result = job.metadata.get("signature_detection", {})
                if sig_result.get("redaction_applied"):
                    image_features_redacted = True
            
            # 4. Extract text
            self.job_manager.update_job(
                job.id, 
                status=JobStatus.EXTRACTING,
                progress=0.3,
                status_message="Extracting text...",
            )
            
            logger.info(f"Extracting text from {job.filename}")
            extraction = extractor.extract(content, job.filename)
            
            # Check page limit
            if extraction.pages > MAX_DOCUMENT_PAGES:
                job.set_error(f"Document exceeds {MAX_DOCUMENT_PAGES} page limit ({extraction.pages} pages)")
                return
            
            # Update page count
            if extraction.pages > 1:
                self.job_manager.update_job(
                    job.id,
                    pages_total=extraction.pages,
                    pages_processed=extraction.pages,
                    status_message=f"Extracting text ({extraction.pages} pages)...",
                )
            
            # Check if OCR was needed
            if extraction.needs_ocr:
                self.job_manager.update_job(
                    job.id,
                    status=JobStatus.OCR,
                    progress=0.5,
                    status_message="Running OCR...",
                )
            
            # Check for extraction errors
            if not extraction.text and extraction.warnings:
                job.set_error(f"Extraction failed: {extraction.warnings[0]}")
                return
            
            # 5. Run PHI detection (for visual redaction only)
            # Full pipeline (coref, tokenization) runs at chat time
            self.job_manager.update_job(
                job.id,
                status=JobStatus.DETECTING,
                progress=0.7,
                status_message="Detecting PHI...",
            )
            
            logger.info(f"Running PHI detection on {job.filename}")
            logger.info(f"Extracted text length: {len(extraction.text)} chars")
            if extraction.text:
                logger.info(f"Extracted text preview: {extraction.text[:200]!r}...")

            # Get pre-extracted PHI from document parsing (if available)
            pre_extracted_spans = []
            if extraction.phi_fields:
                logger.info(
                    f"Document intelligence: type={extraction.document_type}, "
                    f"is_id={extraction.is_id_document}, "
                    f"phi_fields={len(extraction.phi_fields)}"
                )
                pre_extracted_spans = phi_fields_to_spans(
                    extraction.text,
                    extraction.phi_fields,
                    detector_name=f"doc_template:{extraction.document_type or 'unknown'}"
                )
            
            # Run standard detection pipeline
            detection_spans = self.cr.detect_for_visual_redaction(extraction.text)
            
            # Merge pre-extracted spans with detected spans
            # Pre-extracted spans have STRUCTURED tier (high authority)
            if pre_extracted_spans:
                # Add pre-extracted spans that don't overlap with existing detections
                existing_ranges = set()
                for span in detection_spans:
                    existing_ranges.add((span.start, span.end))
                
                for span in pre_extracted_spans:
                    # Check if this span overlaps with any existing detection
                    overlaps = any(
                        not (span.end <= existing[0] or span.start >= existing[1])
                        for existing in existing_ranges
                    )
                    if not overlaps:
                        detection_spans.append(span)
                        existing_ranges.add((span.start, span.end))
                
                logger.info(
                    f"Merged {len(pre_extracted_spans)} pre-extracted spans, "
                    f"total spans: {len(detection_spans)}"
                )
            
            # 6. Visual redaction (face blur + PHI redaction for images/scanned PDFs)
            has_redacted_image = False

            # Check if visual redaction applies
            # Store image if: (a) PHI text was detected, OR (b) faces/signatures were redacted
            has_content_to_redact = detection_spans or image_features_redacted
            needs_visual_redaction = (
                self.enable_image_redaction and
                self.image_store and
                has_content_to_redact and
                extraction.page_infos and
                (is_image or extraction.has_scanned_pages)
            )

            # Fallback: if faces were redacted but page_infos is empty (OCR unavailable),
            # store the face-blurred image directly
            if (
                is_image and
                image_features_redacted and
                self.enable_image_redaction and
                self.image_store and
                not extraction.page_infos
            ):
                from ..storage import ImageFileType
                try:
                    self.image_store.store(
                        job_id=job.id,
                        file_type=ImageFileType.REDACTED,
                        image_bytes=content,  # Face-blurred content
                        original_filename=job.filename,
                        content_type="image/png",
                    )
                    has_redacted_image = True
                    logger.info(f"Stored face-redacted image for {job.filename} (no OCR)")
                except Exception as e:
                    logger.error(f"Failed to store face-redacted image: {e}")

            if needs_visual_redaction:
                self.job_manager.update_job(
                    job.id,
                    progress=0.85,
                    status_message=f"Redacting PHI in {'image' if is_image else 'scanned pages'}...",
                )
                try:
                    has_redacted_image = self._apply_visual_redaction(
                        job, content, extraction, detection_spans, is_image
                    )
                except Exception as e:
                    logger.error(f"Visual redaction failed: {e}", exc_info=True)
            
            # 7. Complete job
            # Store raw extracted_text - tokenization happens at chat time
            processing_time = (time.perf_counter() - start_time) * 1000
            
            self.job_manager.complete_job(
                job.id,
                extracted_text=extraction.text,
                redacted_text=extraction.text,  # Raw text, not tokenized
                spans=detection_spans,           # Detection spans (no tokens)
                processing_time_ms=processing_time,
                ocr_confidence=extraction.confidence if extraction.needs_ocr else None,
                has_redacted_image=has_redacted_image,
            )
            
            logger.info(
                f"Processed {job.filename}: "
                f"{len(detection_spans)} PHI entities detected, "
                f"{processing_time:.0f}ms"
                f"{', redacted image available' if has_redacted_image else ''}"
            )
            
        except Exception as e:
            logger.error(f"Job {job.id} failed: {e}", exc_info=True)
            job.set_error(str(e))
        
        finally:
            # Clean up temp directory
            if temp_dir:
                try:
                    temp_dir.cleanup()
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp dir: {e}")
    
    def get_job(self, job_id: str) -> Optional[FileJob]:
        """Get job by ID."""
        return self.job_manager.get_job(job_id)
    
    def get_job_result(self, job_id: str) -> Optional[dict]:
        """
        Get job result (only if complete).

        Returns:
            Result dict, or None if not found/not complete
        """
        job = self.job_manager.get_job(job_id)
        if not job:
            return None
        return job.to_result_dict()

    def get_job_results_batch(self, job_ids: List[str]) -> Dict[str, dict]:
        """
        Get multiple job results in a single operation (N+1 fix).

        Args:
            job_ids: List of job IDs to fetch

        Returns:
            Dict mapping job_id to result dict (only complete jobs included)
        """
        jobs = self.job_manager.get_jobs_batch(job_ids)
        return {
            job_id: job.to_result_dict()
            for job_id, job in jobs.items()
            if job.to_result_dict() is not None
        }

    def list_jobs(
        self,
        conversation_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[FileJob]:
        """List jobs, optionally filtered by conversation."""
        return self.job_manager.list_jobs(
            conversation_id=conversation_id,
            limit=limit,
        )
    
    def warm_up(self) -> dict:
        """
        Pre-warm all processing engines.
        
        Call after unlock to reduce first-use latency.
        
        Returns:
            Dict with status of each component
        """
        results = {}
        
        # Warm up OCR
        results['ocr'] = self.ocr_engine.warm_up()
        
        # Warm up face detection
        if self.enable_face_detection and self.face_protector:
            results['face_detection'] = self.face_protector.warm_up()
        else:
            results['face_detection'] = None
        
        # Metadata stripper doesn't need warm-up
        results['metadata_stripper'] = self.enable_metadata_stripping
        
        return results
    
    def warm_up_ocr(self) -> bool:
        """
        Pre-warm OCR engine only.
        
        Call after unlock to reduce first-use latency.
        """
        return self.ocr_engine.warm_up()
    
    def get_capabilities(self) -> dict:
        """
        Get current processor capabilities.
        
        Returns:
            Dict describing enabled features and available models
        """
        caps = {
            'ocr': {
                'enabled': True,
                'available': self.ocr_engine.is_available,
            },
            'metadata_stripping': {
                'enabled': self.enable_metadata_stripping,
                'available': self.metadata_stripper is not None,
            },
            'face_detection': {
                'enabled': self.enable_face_detection,
                'available': self.face_protector is not None and self.face_protector.is_available,
                'method': self.face_redaction_method,
            },
        }
        
        if self.face_protector and self.face_protector.is_available:
            # Provide model info if detector is initialized
            detector = self.face_protector.detector
            if detector is not None:
                caps['face_detection']['model_path'] = str(detector.model_path)
                caps['face_detection']['score_threshold'] = detector.score_threshold

        return caps
    
    def shutdown(self) -> None:
        """Shutdown thread pool."""
        self._executor.shutdown(wait=False)
