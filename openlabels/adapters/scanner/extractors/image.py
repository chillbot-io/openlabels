"""Image text extractor using OCR with document intelligence."""

import io
import logging
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from ..constants import MAX_DOCUMENT_PAGES
from .base import BaseExtractor, ExtractionResult, PageInfo

if TYPE_CHECKING:
    from ..ocr import OCREngine
    from ..temp_storage import SecureTempDir

logger = logging.getLogger(__name__)


class ImageExtractor(BaseExtractor):
    """Image text extractor using OCR with document intelligence."""

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
                logger.info("EnhancedOCRProcessor initialized for document intelligence")
            except (ImportError, OSError, ValueError) as e:
                logger.warning(f"Could not initialize EnhancedOCRProcessor: {e}")
                self.enable_enhanced_processing = False
        return self._enhanced_processor

    def _save_page_image(self, img, page_num: int) -> Optional[str]:
        if not self.temp_dir:
            return None
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        temp_path = self.temp_dir.write_page(page_num, img_buffer.getvalue())
        return str(temp_path)

    def can_handle(self, content_type: str, extension: str) -> bool:
        return (
            content_type.startswith("image/") or
            extension in (".jpg", ".jpeg", ".png", ".tiff", ".tif",
                         ".heic", ".heif", ".gif", ".bmp", ".webp")
        )

    def extract(
        self,
        content: bytes,
        filename: str,
        save_pages: bool = True,
    ) -> ExtractionResult:
        if not self.ocr_engine or not self.ocr_engine.is_available:
            return ExtractionResult(
                text="",
                pages=1,
                needs_ocr=True,
                warnings=["OCR engine not available for image extraction"],
            )

        ext = Path(filename).suffix.lower()

        try:
            from PIL import Image
            import numpy as np

            if ext in (".heic", ".heif"):
                try:
                    from pillow_heif import register_heif_opener
                    register_heif_opener()
                except ImportError:
                    return ExtractionResult(
                        text="",
                        pages=1,
                        warnings=["HEIC support not available. Run: pip install pillow-heif"],
                    )

            if ext in (".tiff", ".tif"):
                return self._extract_multipage_tiff(content, filename, save_pages)

            img = Image.open(io.BytesIO(content))  # MED-006: closed in finally
            try:
                if img.mode not in ("RGB", "L"):
                    img = img.convert("RGB")

                img_array = np.array(img)
                temp_path = self._save_page_image(img, 0) if save_pages else None
                ocr_result = self.ocr_engine.extract_with_coordinates(img)

                document_type = None
                is_id_document = False
                phi_fields = None
                enhanced_text = None
                enhancements = []

                if self.enable_enhanced_processing and self.enhanced_processor and ocr_result.blocks:
                    try:
                        enhanced_result = self.enhanced_processor.process(
                            image=img_array,
                            ocr_result=ocr_result,
                            apply_document_cleaning=True,
                        )

                        document_type = enhanced_result.document_type.name
                        is_id_document = enhanced_result.is_id_card
                        phi_fields = enhanced_result.phi_fields
                        enhanced_text = enhanced_result.enhanced_text
                        enhancements = enhanced_result.enhancements_applied

                        logger.info(
                            f"Document intelligence: type={document_type}, "
                            f"is_id={is_id_document}, "
                            f"phi_fields={len(phi_fields) if phi_fields else 0}, "
                            f"enhancements={enhancements}"
                        )

                    except (ValueError, RuntimeError) as e:
                        logger.warning(f"Enhanced OCR processing failed, using raw OCR: {e}")
                        enhancements.append(f"enhanced_failed:{str(e)[:50]}")

                page_info = PageInfo(
                    page_num=0,
                    text=enhanced_text or ocr_result.full_text,
                    is_scanned=True,
                    ocr_result=ocr_result,
                    temp_image_path=temp_path,
                )

                return ExtractionResult(
                    text=ocr_result.full_text,
                    pages=1,
                    needs_ocr=True,
                    ocr_pages=[0],
                    confidence=ocr_result.confidence,
                    ocr_results=[ocr_result],
                    page_infos=[page_info],
                    temp_dir_path=str(self.temp_dir.path) if self.temp_dir and self.temp_dir.path else None,
                    document_type=document_type,
                    is_id_document=is_id_document,
                    phi_fields=phi_fields,
                    enhanced_text=enhanced_text,
                    enhancements_applied=enhancements,
                )
            finally:
                img.close()

        except (OSError, ValueError) as e:
            logger.error(f"Image extraction failed: {e}")
            return ExtractionResult(
                text="",
                pages=1,
                warnings=[f"Image extraction failed: {e}"],
            )

    def _extract_multipage_tiff(
        self,
        content: bytes,
        filename: str,
        save_pages: bool = True,
    ) -> ExtractionResult:
        from PIL import Image
        import numpy as np

        img = Image.open(io.BytesIO(content))  # MED-006: closed in finally
        try:
            pages_text = []
            page_infos = []
            ocr_results = []
            confidences = []

            document_type = None
            is_id_document = False
            phi_fields = None
            enhanced_texts = []
            enhancements = []

            try:
                page_num = 0
                while True:
                    if page_num >= MAX_DOCUMENT_PAGES:
                        logger.warning(f"TIFF exceeds {MAX_DOCUMENT_PAGES} page limit, truncating")
                        break

                    img.seek(page_num)
                    frame = img.convert("RGB")
                    frame_array = np.array(frame)
                    temp_path = self._save_page_image(frame, page_num) if save_pages else None
                    ocr_result = self.ocr_engine.extract_with_coordinates(frame)
                    enhanced_text = ocr_result.full_text

                    if self.enable_enhanced_processing and self.enhanced_processor and ocr_result.blocks:
                        try:
                            enhanced_result = self.enhanced_processor.process(
                                image=frame_array,
                                ocr_result=ocr_result,
                                apply_document_cleaning=True,
                            )

                            enhanced_text = enhanced_result.enhanced_text

                            if page_num == 0:
                                document_type = enhanced_result.document_type.name
                                is_id_document = enhanced_result.is_id_card
                                phi_fields = enhanced_result.phi_fields
                                enhancements = enhanced_result.enhancements_applied

                        except (ValueError, RuntimeError) as e:
                            logger.warning(f"Enhanced processing failed for page {page_num}: {e}")

                    pages_text.append(ocr_result.full_text)
                    enhanced_texts.append(enhanced_text)
                    ocr_results.append(ocr_result)
                    confidences.append(ocr_result.confidence)

                    page_infos.append(PageInfo(
                        page_num=page_num,
                        text=enhanced_text,
                        is_scanned=True,
                        ocr_result=ocr_result,
                        temp_image_path=temp_path,
                    ))

                    page_num += 1

            except EOFError:
                pass

            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

            return ExtractionResult(
                text="\n\n".join(pages_text),
                pages=len(pages_text),
                needs_ocr=True,
                ocr_pages=list(range(len(pages_text))),
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
            img.close()
