"""
Image Protection module for ScrubIQ.

Provides HIPAA-compliant image protection through:
1. Metadata Stripping - Removes all EXIF, XMP, IPTC, and document metadata
2. Face Detection & Redaction - Detects and blurs faces in images
3. Signature Detection & Redaction - Detects and black-boxes signatures
4. Barcode Detection & Redaction - Detects and black-boxes barcodes/QR codes
5. Handwriting Detection - Detects handwritten text for targeted OCR
6. Document Layout Analysis - Detects document structure for smarter processing

Processing Order (Critical for Security):
1. Strip ALL metadata (including thumbnails that may contain unredacted faces)
2. Detect and redact faces
3. Detect and redact signatures
4. Detect and redact barcodes
5. Detect handwriting regions (for targeted OCR)
6. Analyze document layout (for OCR improvement)
"""

__all__ = [
    # Metadata
    "MetadataStripper",
    "MetadataStrippingResult",
    "FileType",
    # Face detection
    "FaceDetector",
    "FaceRedactor",
    "FaceProtector",
    "FaceDetection",
    "FaceRedactionResult",
    "RedactionMethod",
    # Signature detection
    "SignatureDetector",
    "SignatureRedactor",
    "SignatureProtector",
    "SignatureDetection",
    "SignatureRedactionResult",
    # Barcode detection
    "BarcodeDetector",
    "BarcodeDetection",
    "BarcodeDetectionResult",
    # Handwriting detection
    "HandwritingDetector",
    "HandwritingDetection",
    "HandwritingDetectionResult",
    # Document layout
    "DocumentLayoutDetector",
    "LayoutRegion",
    "LayoutAnalysisResult",
    "LayoutClass",
]

def __getattr__(name):
    """Lazy import for heavy modules."""
    if name in ("MetadataStripper", "MetadataStrippingResult", "FileType"):
        from .metadata_stripper import MetadataStripper, MetadataStrippingResult, FileType
        return {"MetadataStripper": MetadataStripper, "MetadataStrippingResult": MetadataStrippingResult, "FileType": FileType}[name]
    
    if name in ("FaceDetector", "FaceRedactor", "FaceProtector", "FaceDetection", "FaceRedactionResult", "RedactionMethod"):
        from .face_detection import FaceDetector, FaceRedactor, FaceProtector, FaceDetection, FaceRedactionResult, RedactionMethod
        return {"FaceDetector": FaceDetector, "FaceRedactor": FaceRedactor, "FaceProtector": FaceProtector, "FaceDetection": FaceDetection, "FaceRedactionResult": FaceRedactionResult, "RedactionMethod": RedactionMethod}[name]
    
    if name in ("SignatureDetector", "SignatureRedactor", "SignatureProtector", "SignatureDetection", "SignatureRedactionResult"):
        from .signature_detection import SignatureDetector, SignatureRedactor, SignatureProtector, SignatureDetection, SignatureRedactionResult
        return {"SignatureDetector": SignatureDetector, "SignatureRedactor": SignatureRedactor, "SignatureProtector": SignatureProtector, "SignatureDetection": SignatureDetection, "SignatureRedactionResult": SignatureRedactionResult}[name]
    
    if name in ("BarcodeDetector", "BarcodeDetection", "BarcodeDetectionResult"):
        from .barcode_detection import BarcodeDetector, BarcodeDetection, BarcodeDetectionResult
        return {"BarcodeDetector": BarcodeDetector, "BarcodeDetection": BarcodeDetection, "BarcodeDetectionResult": BarcodeDetectionResult}[name]
    
    if name in ("HandwritingDetector", "HandwritingDetection", "HandwritingDetectionResult"):
        from .handwriting_detection import HandwritingDetector, HandwritingDetection, HandwritingDetectionResult
        return {"HandwritingDetector": HandwritingDetector, "HandwritingDetection": HandwritingDetection, "HandwritingDetectionResult": HandwritingDetectionResult}[name]
    
    if name in ("DocumentLayoutDetector", "LayoutRegion", "LayoutAnalysisResult", "LayoutClass"):
        from .document_layout import DocumentLayoutDetector, LayoutRegion, LayoutAnalysisResult, LayoutClass
        return {"DocumentLayoutDetector": DocumentLayoutDetector, "LayoutRegion": LayoutRegion, "LayoutAnalysisResult": LayoutAnalysisResult, "LayoutClass": LayoutClass}[name]
    
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
