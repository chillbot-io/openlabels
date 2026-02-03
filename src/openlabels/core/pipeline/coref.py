"""Coreference resolution for NAME-family entities.

Expands NAME-family detections to include pronouns and possessives.
Runs AFTER merger on clean, non-overlapping spans.
Uses ONNX FastCoref when available, falls back to rule-based matching.

Scope:
- Only NAME types: NAME, NAME_PATIENT, NAME_PROVIDER, NAME_RELATIVE
- Pronouns expanded: he, she, they, him, her, them, his, her, their
- NOT applied to: SSN, phone numbers, dates, or other non-name entities

Constraints:
- Window limit: +/-2 sentences from anchor
- Cap per anchor: Maximum 3 pronoun expansions
- Confidence floor: anchor.confidence >= 0.85
- New span confidence = anchor.confidence * 0.90
"""

import heapq
import json
import logging
import re
import threading
from pathlib import Path
from typing import List, Set, Optional, Tuple, Dict

import numpy as np

from ..types import Span, Tier
from .span_validation import validate_after_coref


logger = logging.getLogger(__name__)

# Lock for thread-safe initialization of global caches
_INIT_LOCK = threading.Lock()

# NAME-family types eligible for coreference expansion
NAME_TYPES = frozenset([
    "NAME",
    "NAME_PATIENT",
    "NAME_PROVIDER",
    "NAME_RELATIVE",
])

# Pronouns to expand
PRONOUNS = frozenset([
    "he", "she", "they",
    "him", "her", "them",
    "his", "hers", "their", "theirs",
])

# ONNX FASTCOREF INTEGRATION

_ONNX_SESSION = None
_TOKENIZER = None
_USE_FAST_TOKENIZER = False
_ONNX_AVAILABLE = None
_MODELS_DIR: Optional[Path] = None


def set_models_dir(path: Path) -> None:
    """Set custom models directory (call before first use)."""
    global _MODELS_DIR, _ONNX_AVAILABLE
    _MODELS_DIR = path
    _ONNX_AVAILABLE = None  # Reset availability check


def _get_model_paths() -> Tuple[Path, Path, Path, Path]:
    """Get paths for FastCoref model files."""
    if _MODELS_DIR is None:
        from openlabels.core.constants import DEFAULT_MODELS_DIR
        models_dir = DEFAULT_MODELS_DIR
    else:
        models_dir = _MODELS_DIR
    return (
        models_dir / "fastcoref.onnx",
        models_dir / "fastcoref.tokenizer.json",
        models_dir / "fastcoref_tokenizer",
        models_dir / "fastcoref.config.json",
    )


def _check_onnx_available() -> bool:
    """Check if ONNX FastCoref model is available."""
    global _ONNX_AVAILABLE
    if _ONNX_AVAILABLE is not None:
        return _ONNX_AVAILABLE

    onnx_path, tokenizer_json_path, tokenizer_dir_path, _ = _get_model_paths()

    if not onnx_path.exists():
        logger.warning(
            f"FastCoref ONNX model not found at {onnx_path} - using rule-based fallback"
        )
        _ONNX_AVAILABLE = False
        return False

    # Check for tokenizer (either standalone or HF directory)
    if not tokenizer_json_path.exists() and not tokenizer_dir_path.exists():
        logger.warning(
            f"FastCoref tokenizer not found - using rule-based fallback"
        )
        _ONNX_AVAILABLE = False
        return False

    try:
        import onnxruntime
        # Check for tokenizer library (preferred) or transformers (fallback)
        try:
            from tokenizers import Tokenizer
        except ImportError:
            from transformers import AutoTokenizer
        _ONNX_AVAILABLE = True
        logger.info("FastCoref ONNX model available")
    except ImportError as e:
        logger.warning(f"Required packages not available: {e} - using rule-based fallback")
        _ONNX_AVAILABLE = False

    return _ONNX_AVAILABLE


def _get_onnx_session():
    """Lazy-load ONNX session (thread-safe)."""
    global _ONNX_SESSION

    # Fast path: already loaded
    if _ONNX_SESSION is not None:
        return _ONNX_SESSION

    # Slow path: acquire lock and load
    with _INIT_LOCK:
        # Double-check after acquiring lock
        if _ONNX_SESSION is not None:
            return _ONNX_SESSION

        import onnxruntime as ort

        onnx_path, _, _, _ = _get_model_paths()

        # Prefer CPU for consistency
        providers = ['CPUExecutionProvider']
        try:
            if ort.get_device() == 'GPU':
                providers = ['CUDAExecutionProvider', 'CPUExecutionProvider']
        except (RuntimeError, AttributeError) as e:
            logger.debug(f"Could not detect GPU, using CPU: {e}")

        _ONNX_SESSION = ort.InferenceSession(str(onnx_path), providers=providers)
        logger.info(f"FastCoref ONNX loaded with providers: {_ONNX_SESSION.get_providers()}")

    return _ONNX_SESSION


def _get_tokenizer():
    """Lazy-load tokenizer (thread-safe). Prefers standalone .tokenizer.json."""
    global _TOKENIZER, _USE_FAST_TOKENIZER

    # Fast path: already loaded
    if _TOKENIZER is not None:
        return _TOKENIZER, _USE_FAST_TOKENIZER

    # Slow path: acquire lock and load
    with _INIT_LOCK:
        # Double-check after acquiring lock
        if _TOKENIZER is not None:
            return _TOKENIZER, _USE_FAST_TOKENIZER

        _, tokenizer_json_path, tokenizer_dir_path, _ = _get_model_paths()

        # Try standalone tokenizer first (no transformers needed)
        if tokenizer_json_path.exists():
            from tokenizers import Tokenizer
            _TOKENIZER = Tokenizer.from_file(str(tokenizer_json_path))
            _TOKENIZER.enable_truncation(max_length=512)
            _TOKENIZER.no_padding()
            _USE_FAST_TOKENIZER = True
            logger.info("FastCoref tokenizer loaded (standalone, dynamic length)")
            return _TOKENIZER, _USE_FAST_TOKENIZER

        # Fallback to HuggingFace tokenizer
        if tokenizer_dir_path.exists():
            from transformers import AutoTokenizer
            _TOKENIZER = AutoTokenizer.from_pretrained(str(tokenizer_dir_path))
            _USE_FAST_TOKENIZER = False
            logger.info("FastCoref tokenizer loaded (HuggingFace)")
            return _TOKENIZER, _USE_FAST_TOKENIZER

        raise FileNotFoundError(
            f"No tokenizer found. Expected {tokenizer_json_path} or {tokenizer_dir_path}"
        )


def _tokenize_for_coref(text: str) -> Tuple[np.ndarray, np.ndarray, List[Tuple[int, int]]]:
    """Tokenize text for coref model."""
    tokenizer, is_fast = _get_tokenizer()

    if is_fast:
        encoded = tokenizer.encode(text)
        input_ids = np.array([encoded.ids], dtype=np.int64)
        attention_mask = np.array([encoded.attention_mask], dtype=np.int64)
        offset_mapping = encoded.offsets
    else:
        inputs = tokenizer(
            text,
            return_tensors="np",
            padding=False,
            truncation=True,
            max_length=512,
            return_offsets_mapping=True,
        )
        input_ids = inputs['input_ids']
        attention_mask = inputs['attention_mask']
        offset_mapping = inputs['offset_mapping'][0].tolist()
        offset_mapping = [(int(s), int(e)) for s, e in offset_mapping]

    return input_ids, attention_mask, offset_mapping


def _get_mention_candidates(
    start_scores: np.ndarray,
    end_scores: np.ndarray,
    attention_mask: np.ndarray,
    max_span_length: int = 30,
    top_k: int = 50,
) -> List[Tuple[int, int, float]]:
    """Extract top-k mention span candidates from start/end scores."""
    valid_len = int(attention_mask.sum())

    # Use a min-heap of size top_k for efficient top-k selection
    heap: List[Tuple[float, int, int]] = []

    for start in range(1, valid_len - 1):  # Skip [CLS] and [SEP]
        for end in range(start, min(start + max_span_length, valid_len - 1)):
            score = float(start_scores[start] + end_scores[end])

            if len(heap) < top_k:
                heapq.heappush(heap, (score, start, end))
            elif score > heap[0][0]:
                heapq.heapreplace(heap, (score, start, end))

    result = [(start, end, score) for score, start, end in heap]
    result.sort(key=lambda x: x[2], reverse=True)
    return result


def _compute_antecedent_scores(
    mentions: List[Tuple[int, int, float]],
    ante_s2s: np.ndarray,
    ante_e2e: np.ndarray,
    ante_s2e: np.ndarray,
    ante_e2s: np.ndarray,
    mention_s2e: np.ndarray,
    end_mention: np.ndarray,
) -> np.ndarray:
    """Compute pairwise antecedent scores between mentions."""
    n = len(mentions)
    if n == 0:
        return np.zeros((0, 0))

    scores = np.zeros((n, n))

    for i, (s_i, e_i, _) in enumerate(mentions):
        for j, (s_j, e_j, _) in enumerate(mentions):
            if j >= i:  # Antecedent must come before
                continue

            # Bilinear scoring
            score = (
                np.dot(ante_s2s[s_i], ante_s2s[s_j]) +
                np.dot(ante_e2e[e_i], ante_e2e[e_j]) +
                np.dot(ante_s2e[s_i], end_mention[e_j]) +
                np.dot(ante_e2s[e_i], mention_s2e[s_j])
            )
            scores[i, j] = score

    return scores


def _cluster_mentions(
    mentions: List[Tuple[int, int, float]],
    antecedent_scores: np.ndarray,
    threshold: float = 0.0,
) -> List[List[Tuple[int, int]]]:
    """Greedily cluster mentions based on antecedent scores."""
    n = len(mentions)
    if n == 0:
        return []

    cluster_id = [-1] * n
    clusters: Dict[int, List[int]] = {}
    next_cluster = 0

    for i in range(n):
        best_ante = -1
        best_score = threshold

        for j in range(i):
            if antecedent_scores[i, j] > best_score:
                best_score = antecedent_scores[i, j]
                best_ante = j

        if best_ante >= 0:
            ante_cluster = cluster_id[best_ante]
            cluster_id[i] = ante_cluster
            clusters[ante_cluster].append(i)
        else:
            cluster_id[i] = next_cluster
            clusters[next_cluster] = [i]
            next_cluster += 1

    result = []
    for cid in sorted(clusters.keys()):
        cluster_spans = [(mentions[i][0], mentions[i][1]) for i in clusters[cid]]
        if len(cluster_spans) > 1:
            result.append(cluster_spans)

    return result


def _token_spans_to_char_spans(
    token_spans: List[Tuple[int, int]],
    offset_mapping: List[Tuple[int, int]],
) -> List[Tuple[int, int]]:
    """Convert token indices to character offsets."""
    char_spans = []
    for tok_start, tok_end in token_spans:
        if tok_start < len(offset_mapping) and tok_end < len(offset_mapping):
            char_start = offset_mapping[tok_start][0]
            char_end = offset_mapping[tok_end][1]
            if char_start < char_end:
                char_spans.append((char_start, char_end))
    return char_spans


def _resolve_with_onnx(
    text: str,
    spans: List[Span],
    window_sentences: int,
    max_expansions_per_anchor: int,
    min_anchor_confidence: float,
    confidence_decay: float,
) -> List[Span]:
    """Resolve coreferences using ONNX FastCoref model."""
    session = _get_onnx_session()

    # Tokenize with offset mapping
    input_ids, attention_mask, offset_mapping = _tokenize_for_coref(text)

    # Run ONNX inference
    outputs = session.run(
        None,
        {
            'input_ids': input_ids,
            'attention_mask': attention_mask,
        }
    )

    # Unpack outputs
    mention_start_scores = outputs[0][0]
    mention_end_scores = outputs[1][0]
    mention_s2e = outputs[2][0]
    end_mention = outputs[3][0]
    ante_s2s = outputs[4][0]
    ante_e2e = outputs[5][0]
    ante_s2e = outputs[6][0]
    ante_e2s = outputs[7][0]

    # Get mention candidates
    mentions = _get_mention_candidates(
        mention_start_scores,
        mention_end_scores,
        attention_mask[0],
    )

    if not mentions:
        return list(spans)

    # Compute antecedent scores
    antecedent_scores = _compute_antecedent_scores(
        mentions, ante_s2s, ante_e2e, ante_s2e, ante_e2s, mention_s2e, end_mention
    )

    # Cluster mentions
    clusters = _cluster_mentions(mentions, antecedent_scores)

    if not clusters:
        return list(spans)

    # Convert clusters to char offsets
    char_clusters = []
    for cluster in clusters:
        char_spans = _token_spans_to_char_spans(cluster, offset_mapping)
        if char_spans:
            char_clusters.append(char_spans)

    # Build anchor lookup
    name_anchors: Dict[Tuple[int, int], Span] = {}
    for s in spans:
        if s.entity_type in NAME_TYPES and s.confidence >= min_anchor_confidence:
            name_anchors[(s.start, s.end)] = s

    if not name_anchors:
        return list(spans)

    # Split text into sentences for window checking
    sentences = _split_sentences(text)

    # Track covered positions and expansions
    covered: Set[Tuple[int, int]] = {(s.start, s.end) for s in spans}
    anchor_expansion_count: Dict[int, int] = {}
    new_spans = []

    def find_overlapping_anchor(start: int, end: int) -> Optional[Span]:
        for (a_start, a_end), anchor in name_anchors.items():
            if start < a_end and end > a_start:
                return anchor
        return None

    def overlaps_covered(start: int, end: int) -> bool:
        for (c_start, c_end) in covered:
            if start < c_end and end > c_start:
                return True
        return False

    # Process each cluster
    for cluster_chars in char_clusters:
        # Find anchor in this cluster
        anchor_span = None
        for (start, end) in cluster_chars:
            anchor_span = find_overlapping_anchor(start, end)
            if anchor_span:
                break

        if anchor_span is None:
            continue

        anchor_id = id(anchor_span)
        if anchor_id not in anchor_expansion_count:
            anchor_expansion_count[anchor_id] = 0

        anchor_sent_idx = _get_sentence_index(anchor_span.start, sentences)

        # Expand to other mentions (only pronouns)
        for (start, end) in cluster_chars:
            if overlaps_covered(start, end):
                continue

            mention_text = text[start:end]

            # Only expand to pronouns
            if mention_text.lower() not in PRONOUNS:
                continue

            # Check expansion cap
            if anchor_expansion_count[anchor_id] >= max_expansions_per_anchor:
                break

            # Check window constraint
            mention_sent_idx = _get_sentence_index(start, sentences)
            if abs(mention_sent_idx - anchor_sent_idx) > window_sentences:
                continue

            new_span = Span(
                start=start,
                end=end,
                text=mention_text,
                entity_type=anchor_span.entity_type,
                confidence=anchor_span.confidence * confidence_decay,
                detector="fastcoref_onnx",
                tier=Tier.ML,
                coref_anchor_value=anchor_span.text,
            )

            new_spans.append(new_span)
            covered.add((start, end))
            anchor_expansion_count[anchor_id] += 1

    result = list(spans) + new_spans
    result.sort(key=lambda s: s.start)
    return result


# RULE-BASED FALLBACK
MALE_PRONOUNS = frozenset(["he", "him", "his"])
FEMALE_PRONOUNS = frozenset(["she", "her", "hers"])
NEUTRAL_PRONOUNS = frozenset(["they", "them", "their", "theirs"])

PRONOUN_PATTERN = re.compile(
    r'\b(' + '|'.join(PRONOUNS) + r')\b',
    re.IGNORECASE
)

ABBREVIATIONS = {'Dr', 'Mr', 'Mrs', 'Ms', 'Jr', 'Sr', 'Prof', 'Rev', 'vs', 'etc', 'Inc', 'Ltd', 'Corp'}
SENTENCE_PATTERN = re.compile(r'[.!?]+\s+')

FEMALE_NAMES = frozenset([
    'mary', 'patricia', 'jennifer', 'linda', 'elizabeth', 'barbara', 'susan',
    'jessica', 'sarah', 'karen', 'nancy', 'lisa', 'betty', 'helen', 'sandra',
    'donna', 'carol', 'ruth', 'sharon', 'michelle', 'laura', 'jane', 'anna',
])
MALE_NAMES = frozenset([
    'james', 'john', 'robert', 'michael', 'william', 'david', 'richard',
    'joseph', 'thomas', 'charles', 'christopher', 'daniel', 'matthew', 'anthony',
    'mark', 'donald', 'steven', 'paul', 'andrew', 'joshua', 'kenneth', 'kevin',
])


def _split_sentences(text: str) -> List[Tuple[int, int, str]]:
    """Split text into sentences with positions."""
    sentences = []
    pos = 0

    for match in SENTENCE_PATTERN.finditer(text):
        end = match.end()
        preceding = text[max(0, match.start()-10):match.start()].split()
        if preceding and preceding[-1].rstrip('.') in ABBREVIATIONS:
            continue
        sentences.append((pos, end, text[pos:end]))
        pos = end

    if pos < len(text):
        sentences.append((pos, len(text), text[pos:]))

    return sentences


def _get_sentence_index(pos: int, sentences: List[Tuple[int, int, str]]) -> int:
    """Get sentence index for a character position."""
    for i, (start, end, _) in enumerate(sentences):
        if start <= pos < end:
            return i
    return len(sentences) - 1


def _infer_gender(name: str) -> Optional[str]:
    """Infer likely gender from name."""
    first = name.split()[0].lower().rstrip('.')
    if first in FEMALE_NAMES:
        return 'F'
    if first in MALE_NAMES:
        return 'M'
    return None


def _pronoun_matches_gender(pronoun: str, gender: Optional[str]) -> bool:
    """Check if pronoun is compatible with inferred gender."""
    p = pronoun.lower()
    if p in NEUTRAL_PRONOUNS:
        return True
    if gender is None:
        return True
    if gender == 'M' and p in MALE_PRONOUNS:
        return True
    if gender == 'F' and p in FEMALE_PRONOUNS:
        return True
    return False


def _resolve_with_rules(
    text: str,
    spans: List[Span],
    window_sentences: int,
    max_expansions_per_anchor: int,
    min_anchor_confidence: float,
    confidence_decay: float,
) -> List[Span]:
    """Rule-based pronoun resolution (fallback)."""
    if not spans:
        return []

    # Find NAME anchors
    anchors = []
    for s in spans:
        if s.entity_type in NAME_TYPES and s.confidence >= min_anchor_confidence:
            anchors.append((s, _infer_gender(s.text)))

    if not anchors:
        return list(spans)

    sentences = _split_sentences(text)
    if not sentences:
        return list(spans)

    pronoun_matches = list(PRONOUN_PATTERN.finditer(text))
    if not pronoun_matches:
        return list(spans)

    covered: Set[Tuple[int, int]] = {(s.start, s.end) for s in spans}
    new_spans = []
    anchor_expansions = {id(a): 0 for a, _ in anchors}

    for match in pronoun_matches:
        pstart, pend = match.start(), match.end()
        pronoun = match.group(0)

        if (pstart, pend) in covered:
            continue

        pronoun_sent_idx = _get_sentence_index(pstart, sentences)

        # Find compatible anchor
        compatible = []
        for anchor, gender in anchors:
            if anchor_expansions[id(anchor)] >= max_expansions_per_anchor:
                continue

            anchor_sent_idx = _get_sentence_index(anchor.start, sentences)
            if abs(pronoun_sent_idx - anchor_sent_idx) > window_sentences:
                continue
            if pstart < anchor.end:
                continue
            if not _pronoun_matches_gender(pronoun, gender):
                continue

            compatible.append((anchor, gender))

        if not compatible:
            continue

        # Use closest anchor
        if len(compatible) == 1:
            anchor, _ = compatible[0]
            conf = anchor.confidence * confidence_decay
        else:
            anchor, _ = min(compatible, key=lambda x: pstart - x[0].end)
            conf = anchor.confidence * confidence_decay * 0.8  # Ambiguity penalty

        new_span = Span(
            start=pstart,
            end=pend,
            text=pronoun,
            entity_type=anchor.entity_type,
            confidence=conf,
            detector="coref_rules",
            tier=Tier.ML,
            coref_anchor_value=anchor.text,
        )

        new_spans.append(new_span)
        covered.add((pstart, pend))
        anchor_expansions[id(anchor)] += 1

    result = list(spans) + new_spans
    result.sort(key=lambda s: s.start)
    return result


# PARTIAL NAME LINKING

def _normalize_name_for_matching(text: str) -> str:
    """Normalize name for word-based matching."""
    return text.lower().strip()


def _get_name_words(text: str) -> Set[str]:
    """Extract words from a name, excluding common titles."""
    titles = {"dr", "mr", "mrs", "ms", "prof", "rev", "jr", "sr", "ii", "iii", "iv"}
    words = set(_normalize_name_for_matching(text).replace(".", "").split())
    return words - titles


def _link_partial_names(spans: List[Span], min_confidence: float = 0.70) -> List[Span]:
    """Link partial names to their full name anchors."""
    if not spans:
        return []

    # Collect NAME-type spans eligible for linking
    name_spans: List[Tuple[int, Span]] = []
    for i, span in enumerate(spans):
        if span.entity_type in NAME_TYPES and span.confidence >= min_confidence:
            name_spans.append((i, span))

    if len(name_spans) < 2:
        return list(spans)

    # Build word-to-spans index
    word_to_spans: Dict[str, List[Tuple[int, Span]]] = {}
    span_words: Dict[int, Set[str]] = {}

    for idx, span in name_spans:
        words = _get_name_words(span.text)
        span_words[idx] = words
        for word in words:
            if len(word) >= 2:
                if word not in word_to_spans:
                    word_to_spans[word] = []
                word_to_spans[word].append((idx, span))

    # Group spans that share words using union-find approach
    span_to_group: Dict[int, int] = {}
    groups: Dict[int, Set[int]] = {}
    next_group = 0

    for idx, span in name_spans:
        connected = {idx}
        for word in span_words.get(idx, set()):
            for other_idx, other_span in word_to_spans.get(word, []):
                connected.add(other_idx)

        existing_groups = set()
        for connected_idx in connected:
            if connected_idx in span_to_group:
                existing_groups.add(span_to_group[connected_idx])

        if existing_groups:
            target_group = min(existing_groups)
            for connected_idx in connected:
                span_to_group[connected_idx] = target_group
                groups[target_group].add(connected_idx)
            for other_group in existing_groups:
                if other_group != target_group:
                    for member_idx in groups.get(other_group, set()):
                        span_to_group[member_idx] = target_group
                        groups[target_group].add(member_idx)
                    groups.pop(other_group, None)
        else:
            span_to_group[idx] = next_group
            groups[next_group] = connected
            for connected_idx in connected:
                span_to_group[connected_idx] = next_group
            next_group += 1

    # For each group, find anchor and link others
    result = list(spans)

    for group_id, member_indices in groups.items():
        if len(member_indices) < 2:
            continue

        members = [(idx, spans[idx]) for idx in member_indices]
        anchor_idx, anchor_span = max(
            members,
            key=lambda x: (len(x[1].text), -x[1].start)
        )

        for idx, span in members:
            if idx == anchor_idx:
                continue

            if span.coref_anchor_value:
                continue

            logger.debug(
                f"Partial name link: '{span.text}' -> '{anchor_span.text}'"
            )
            result[idx] = Span(
                start=span.start,
                end=span.end,
                text=span.text,
                entity_type=span.entity_type,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                needs_review=span.needs_review,
                review_reason=span.review_reason,
                coref_anchor_value=anchor_span.text,
            )

    return result


# PUBLIC API

def resolve_coreferences(
    text: str,
    spans: List[Span],
    window_sentences: int = 2,
    max_expansions_per_anchor: int = 3,
    min_anchor_confidence: float = 0.85,
    confidence_decay: float = 0.90,
    use_onnx: Optional[bool] = None,
) -> List[Span]:
    """
    Expand NAME-family detections to include coreferent pronouns and partial names.

    Args:
        text: Original text
        spans: Non-overlapping spans from merger
        window_sentences: Max sentences from anchor (default: 2)
        max_expansions_per_anchor: Cap on expansions (default: 3)
        min_anchor_confidence: Anchor floor (default: 0.85)
        confidence_decay: Multiplier for expanded spans (default: 0.90)
        use_onnx: Force ONNX (True), rules (False), or auto (None)

    Returns:
        Original spans + expanded pronoun spans, with partial names linked
    """
    if not text or not spans:
        return list(spans) if spans else []

    # Determine resolver
    if use_onnx is None:
        use_onnx = _check_onnx_available()
    elif use_onnx and not _check_onnx_available():
        logger.warning("ONNX FastCoref requested but unavailable, using rules")
        use_onnx = False

    # Step 1: Pronoun resolution
    if use_onnx:
        try:
            result = _resolve_with_onnx(
                text, spans, window_sentences, max_expansions_per_anchor,
                min_anchor_confidence, confidence_decay
            )
        except Exception as e:
            logger.error(f"ONNX FastCoref failed: {e}, falling back to rules")
            result = _resolve_with_rules(
                text, spans, window_sentences, max_expansions_per_anchor,
                min_anchor_confidence, confidence_decay
            )
    else:
        result = _resolve_with_rules(
            text, spans, window_sentences, max_expansions_per_anchor,
            min_anchor_confidence, confidence_decay
        )

    # Step 2: Partial name linking
    result = _link_partial_names(result, min_confidence=min_anchor_confidence)

    # Step 3: Validate span positions
    result = validate_after_coref(text, result, strict=False)

    return result


def is_onnx_available() -> bool:
    """Check if ONNX FastCoref is available."""
    return _check_onnx_available()


# Legacy alias
def is_fastcoref_available() -> bool:
    """Check if FastCoref (ONNX) is available."""
    return _check_onnx_available()
