"""PDF text extractor using PyMuPDF."""

import io
import logging
from typing import Optional, TYPE_CHECKING

from ..constants import MIN_NATIVE_TEXT_LENGTH, MAX_DOCUMENT_PAGES
from .base import BaseExtractor, ExtractionResult, PageInfo

if TYPE_CHECKING:
    from ..ocr import OCREngine
    from ..temp_storage import SecureTempDir

logger = logging.getLogger(__name__)


class PDFExtractor(BaseExtractor):
    """PDF text extractor using PyMuPDF with document intelligence."""

    RENDER_DPI = 150

    def __init__(
        self,
        ocr_engine: Optional["OCREngine"] = None,
        temp_dir: Optional["SecureTempDir"] = None,
        enable_enhanced_processing: bool = False,
    ):
        self.ocr_engine = ocr_engine
        self.temp_dir = temp_dir
        self.enable_enhanced_processing = enable_enhanced_processing
        self._enhanced_processor = None

    @property
    def enhanced_processor(self):
        if self._enhanced_processor is None and self.enable_enhanced_processing:
            try:
                from ..enhanced_ocr import EnhancedOCRProcessor
                self._enhanced_processor = EnhancedOCRProcessor()
            except (ImportError, OSError, ValueError) as e:
                logger.warning(f"Could not initialize EnhancedOCRProcessor: {e}")
                self.enable_enhanced_processing = False
        return self._enhanced_processor

    def can_handle(self, content_type: str, extension: str) -> bool:
        return content_type == "application/pdf" or extension == ".pdf"

    def _save_page_image(self, img, page_num: int) -> Optional[str]:
        if not self.temp_dir:
            return None
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        temp_path = self.temp_dir.write_page(page_num, img_buffer.getvalue())
        return str(temp_path)

    def extract(
        self,
        content: bytes,
        filename: str,
        save_scanned_pages: bool = True,
    ) -> ExtractionResult:
        try:
            import fitz
        except ImportError:
            raise ImportError("PyMuPDF not installed. Run: pip install pymupdf")

        doc = fitz.open(stream=content, filetype="pdf")

        pages_text = []
        page_infos = []
        ocr_pages = []
        ocr_results = []
        ocr_confidences = []
        warnings = []

        document_type = None
        is_id_document = False
        phi_fields = None
        enhanced_texts = []
        enhancements = []
        first_scanned_processed = False

        try:
            for i, page in enumerate(doc):
                if i >= MAX_DOCUMENT_PAGES:
                    logger.warning(f"PDF exceeds {MAX_DOCUMENT_PAGES} page limit, truncating")
                    warnings.append(f"Document truncated at {MAX_DOCUMENT_PAGES} pages")
                    break

                native_text = page.get_text().strip()
                has_native_text = len(native_text) >= MIN_NATIVE_TEXT_LENGTH

                if has_native_text:
                    pages_text.append(native_text)
                    enhanced_texts.append(native_text)
                    page_infos.append(PageInfo(
                        page_num=i,
                        text=native_text,
                        is_scanned=False,
                        ocr_result=None,
                        temp_image_path=None,
                    ))
                    logger.debug(f"Page {i+1}: native text ({len(native_text)} chars)")

                elif self.ocr_engine and self.ocr_engine.is_available:
                    logger.debug(f"Page {i+1}: scanned, using OCR")

                    try:
                        pix = page.get_pixmap(dpi=self.RENDER_DPI)
                        from PIL import Image
                        import numpy as np

                        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                        img_array = np.array(img)
                        temp_path = self._save_page_image(img, i) if save_scanned_pages else None
                        ocr_result = self.ocr_engine.extract_with_coordinates(img)
                        enhanced_text = ocr_result.full_text

                        if self.enable_enhanced_processing and self.enhanced_processor and ocr_result.blocks:
                            try:
                                enhanced_result = self.enhanced_processor.process(
                                    image=img_array,
                                    ocr_result=ocr_result,
                                    apply_document_cleaning=True,
                                )

                                enhanced_text = enhanced_result.enhanced_text

                                if not first_scanned_processed:
                                    document_type = enhanced_result.document_type.name
                                    is_id_document = enhanced_result.is_id_card
                                    phi_fields = enhanced_result.phi_fields
                                    enhancements = enhanced_result.enhancements_applied
                                    first_scanned_processed = True

                                    logger.info(
                                        f"PDF document intelligence (page {i+1}): "
                                        f"type={document_type}, is_id={is_id_document}, "
                                        f"phi_fields={len(phi_fields) if phi_fields else 0}"
                                    )

                            except (ValueError, RuntimeError) as e:
                                logger.warning(f"Enhanced processing failed for page {i+1}: {e}")

                        pages_text.append(ocr_result.full_text)
                        enhanced_texts.append(enhanced_text)
                        ocr_pages.append(i)
                        ocr_results.append(ocr_result)
                        ocr_confidences.append(ocr_result.confidence)

                        page_infos.append(PageInfo(
                            page_num=i,
                            text=enhanced_text,
                            is_scanned=True,
                            ocr_result=ocr_result,
                            temp_image_path=temp_path,
                        ))

                    except (OSError, ValueError) as e:
                        logger.warning(f"OCR failed for page {i+1}: {e}")
                        pages_text.append("")
                        enhanced_texts.append("")
                        warnings.append(f"OCR failed for page {i+1}: {e}")
                        page_infos.append(PageInfo(
                            page_num=i,
                            text="",
                            is_scanned=True,
                            ocr_result=None,
                            temp_image_path=None,
                        ))
                else:
                    pages_text.append("")
                    enhanced_texts.append("")
                    page_infos.append(PageInfo(
                        page_num=i,
                        text="",
                        is_scanned=True,
                        ocr_result=None,
                        temp_image_path=None,
                    ))
                    if not self.ocr_engine:
                        warnings.append(f"Page {i+1} is scanned but OCR not available")

            avg_confidence = 1.0
            if ocr_confidences:
                avg_confidence = sum(ocr_confidences) / len(ocr_confidences)

            return ExtractionResult(
                text="\n\n".join(pages_text),
                pages=len(doc),
                needs_ocr=len(ocr_pages) > 0,
                ocr_pages=ocr_pages,
                warnings=warnings,
                confidence=avg_confidence,
                ocr_results=ocr_results,
                page_infos=page_infos,
                temp_dir_path=str(self.temp_dir.path) if self.temp_dir and self.temp_dir.path else None,
                document_type=document_type,
                is_id_document=is_id_document,
                phi_fields=phi_fields,
                enhanced_text="\n\n".join(enhanced_texts) if enhanced_texts else None,
                enhancements_applied=enhancements,
            )

        finally:
            doc.close()
