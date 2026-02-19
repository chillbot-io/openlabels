"""Language detection and detector routing for multilingual pipelines.

Detects the language of input text and determines which detectors should
fire for that language. This avoids running English-only detectors (Stanford
PHI, spaCy NER, dictionary names) on non-English text where they would
produce false positives, and ensures the multilingual GLiNER model is
activated for supported non-English languages.

Supported languages for ML detection (via MultilingualGLiNER):
    EN, ES, FR, PT, DE, IT, EL, NL, SL

Pattern and checksum detectors are language-agnostic and always fire.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# ISO 639-1 codes supported by the E3-JSI multilingual GLiNER model.
MULTILINGUAL_GLINER_LANGS = frozenset({
    "en", "es", "fr", "pt", "de", "it", "el", "nl", "sl",
})


class LanguageTier(Enum):
    """How well the detection pipeline supports a given language."""

    ENGLISH = "english"
    MULTILINGUAL_SUPPORTED = "multilingual_supported"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class LanguageResult:
    """Result of language detection on input text."""

    language_code: str          # ISO 639-1 (e.g. "en", "fr", "unknown")
    confidence: float           # 0.0–1.0
    tier: LanguageTier

    @property
    def is_english(self) -> bool:
        return self.language_code == "en"

    @property
    def is_multilingual_supported(self) -> bool:
        return self.language_code in MULTILINGUAL_GLINER_LANGS


# Lazy-loaded detector singleton (lingua is heavy on first import)
_detector = None


def _get_detector():
    """Get or create the lingua LanguageDetector singleton."""
    global _detector
    if _detector is None:
        try:
            from lingua import Language, LanguageDetectorBuilder

            # Build a detector for languages we care about + a few common extras.
            # Using a focused set is faster and more accurate than ALL.
            languages = [
                Language.ENGLISH, Language.SPANISH, Language.FRENCH,
                Language.PORTUGUESE, Language.GERMAN, Language.ITALIAN,
                Language.GREEK, Language.DUTCH, Language.SLOVENE,
                # Common extras for accurate differentiation
                Language.CHINESE, Language.JAPANESE, Language.KOREAN,
                Language.RUSSIAN, Language.ARABIC, Language.HINDI,
                Language.TURKISH, Language.POLISH, Language.SWEDISH,
                Language.DANISH, Language.BOKMAL,
            ]
            _detector = (
                LanguageDetectorBuilder
                .from_languages(*languages)
                .with_preloaded_language_models()
                .build()
            )
            logger.debug("Lingua language detector initialised")
        except ImportError:
            logger.warning(
                "lingua-language-detector not installed; "
                "language detection disabled (treating all text as English)"
            )
    return _detector


# Map lingua Language enum names to ISO 639-1 codes.
_LINGUA_TO_ISO = {
    "ENGLISH": "en", "SPANISH": "es", "FRENCH": "fr",
    "PORTUGUESE": "pt", "GERMAN": "de", "ITALIAN": "it",
    "GREEK": "el", "DUTCH": "nl", "SLOVENE": "sl",
    "CHINESE": "zh", "JAPANESE": "ja", "KOREAN": "ko",
    "RUSSIAN": "ru", "ARABIC": "ar", "HINDI": "hi",
    "TURKISH": "tr", "POLISH": "pl", "SWEDISH": "sv",
    "DANISH": "da", "BOKMAL": "no",
}


def detect_language(text: str, *, min_length: int = 20) -> LanguageResult:
    """Detect the language of *text*.

    For very short text (< *min_length* chars), assumes English to avoid
    unreliable detection on snippets like email addresses or phone numbers.

    Returns a ``LanguageResult`` with the ISO 639-1 code, confidence, and
    a ``LanguageTier`` indicating how well the pipeline supports it.
    """
    if not text or len(text.strip()) < min_length:
        return LanguageResult(
            language_code="en", confidence=0.5, tier=LanguageTier.ENGLISH,
        )

    detector = _get_detector()
    if detector is None:
        # Fallback: no lingua installed → assume English
        return LanguageResult(
            language_code="en", confidence=0.5, tier=LanguageTier.ENGLISH,
        )

    try:
        result = detector.compute_language_confidence_values(text)
        if not result:
            return LanguageResult(
                language_code="unknown", confidence=0.0, tier=LanguageTier.UNSUPPORTED,
            )

        top = result[0]
        lang_name = top.language.name
        code = _LINGUA_TO_ISO.get(lang_name, "unknown")
        confidence = top.value

        if code == "en":
            tier = LanguageTier.ENGLISH
        elif code in MULTILINGUAL_GLINER_LANGS:
            tier = LanguageTier.MULTILINGUAL_SUPPORTED
        else:
            tier = LanguageTier.UNSUPPORTED

        logger.debug(
            "Language detected: %s (%.2f confidence, tier=%s)",
            code, confidence, tier.value,
        )
        return LanguageResult(language_code=code, confidence=confidence, tier=tier)

    except (RuntimeError, ValueError, AttributeError) as e:
        logger.warning("Language detection failed: %s", e)
        return LanguageResult(
            language_code="en", confidence=0.3, tier=LanguageTier.ENGLISH,
        )


# Detector names that are English-only and should be skipped for non-English text.
ENGLISH_ONLY_DETECTORS = frozenset({
    "stanford_phi",
    "spacy_ner",
    "dictionary_names",
})

# Detector names that only make sense for multilingual-supported languages.
MULTILINGUAL_DETECTORS = frozenset({
    "multilingual_gliner",
})


def should_run_detector(detector_name: str, lang_result: LanguageResult) -> bool:
    """Determine whether a detector should run given the detected language.

    Rules:
    - Pattern/checksum detectors: always run (language-agnostic)
    - English-only ML detectors (PHI, spaCy, dictionary names): English only
    - GLiNER (English): English only
    - Multilingual GLiNER: non-English multilingual-supported languages only
      (for English, the English GLiNER is better)
    - Unsupported languages: patterns/checksums only
    """
    # Pattern/checksum detectors always run
    if detector_name not in ENGLISH_ONLY_DETECTORS | MULTILINGUAL_DETECTORS | {"gliner"}:
        return True

    if lang_result.tier == LanguageTier.ENGLISH:
        # English text: run English-only detectors + GLiNER, skip multilingual
        return detector_name != "multilingual_gliner"

    if lang_result.tier == LanguageTier.MULTILINGUAL_SUPPORTED:
        # Supported non-English: run multilingual GLiNER, skip English-only
        if detector_name in ENGLISH_ONLY_DETECTORS:
            return False
        if detector_name == "gliner":
            return False  # Use multilingual model instead
        return True  # multilingual_gliner runs

    # Unsupported language: skip all ML detectors
    return detector_name not in (ENGLISH_ONLY_DETECTORS | MULTILINGUAL_DETECTORS | {"gliner"})
