"""ONNX-based ML detectors for fast inference.

Loads ONNX models converted by convert_to_onnx.py.
Uses standalone tokenizers (no transformers dependency).

Supports chunking for long documents with proper overlap handling.
"""

import bisect
import json
import logging
import numpy as np
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Dict, Tuple

from ..types import Span, Tier
from ..constants import NON_NAME_WORDS, NAME_CONNECTORS, BERT_MAX_LENGTH, PRODUCT_CODE_PREFIXES
from .base import BaseDetector
from .labels import PHI_BERT_LABELS, PII_BERT_LABELS

logger = logging.getLogger(__name__)


def build_word_boundaries(text: str) -> Tuple[List[int], List[int]]:
    """Pre-compute word boundary positions for O(1) lookups.

    Returns:
        Tuple of (word_starts, word_ends) where:
        - word_starts[i] is the start position of word i
        - word_ends[i] is the end position of word i
    """
    word_starts = []
    word_ends = []

    i = 0
    text_len = len(text)

    while i < text_len:
        # Skip whitespace
        while i < text_len and text[i].isspace():
            i += 1

        if i >= text_len:
            break

        # Found start of word
        word_start = i

        # Find end of word
        while i < text_len and not text[i].isspace():
            i += 1

        word_starts.append(word_start)
        word_ends.append(i)

    return word_starts, word_ends


def expand_to_word_boundary(
    start: int,
    end: int,
    word_starts: List[int],
    word_ends: List[int],
    text_len: int,
) -> Tuple[int, int]:
    """Expand span to word boundaries using pre-computed boundaries.

    Uses binary search for O(log n) lookups instead of O(word_length) iteration.
    """
    if not word_starts:
        return start, end

    # Find word containing start position
    # bisect_right gives us the index of the first word_start > start
    start_idx = bisect.bisect_right(word_starts, start) - 1
    if start_idx >= 0:
        start = word_starts[start_idx]

    # Find word containing end position
    # We want the word that contains end-1 (since end is exclusive)
    end_idx = bisect.bisect_right(word_starts, end - 1) - 1
    if end_idx >= 0 and end_idx < len(word_ends):
        end = word_ends[end_idx]

    return max(0, start), min(text_len, end)


class ONNXDetector(BaseDetector):
    """Base class for ONNX-based NER detectors.
    
    Expects files:
        - {model_name}.onnx: The ONNX model
        - {model_name}.tokenizer.json: Standalone tokenizer (from export_tokenizers.py)
        - {model_name}.labels.json: Label mappings
    
    Falls back to HuggingFace tokenizer directory if .tokenizer.json not found.
    
    Handles long documents via chunking with overlap to catch entities at boundaries.
    """

    name = "onnx"
    tier = Tier.ML
    label_map: Dict[str, str] = {}  # Override in subclass

    # Chunking configuration
    # BERT has 512 token limit, ~4 chars/token average
    # Use conservative estimates to avoid truncation
    CHUNK_MAX_CHARS = 1500      # ~375 tokens, leaves room for special tokens
    CHUNK_STRIDE = 1200         # 300 char overlap to catch boundary entities
    CHUNK_MIN_OVERLAP = 200     # Minimum overlap to ensure entity capture
    CHUNK_PARALLEL_WORKERS = 4  # Max parallel chunk processing threads

    def __init__(self, model_dir: Optional[Path] = None, model_name: str = "model"):
        self.model_dir = model_dir
        self.model_name = model_name
        self._session = None
        self._tokenizer = None
        self._use_fast_tokenizer = False  # True if using tokenizers lib directly
        self._id2label: Dict[int, str] = {}
        self._loaded = False
        self._max_length = BERT_MAX_LENGTH  # Max length for truncation only

    def is_available(self) -> bool:
        return self._loaded

    def _get_onnx_path(self) -> Optional[Path]:
        """Find ONNX model file. Prefers INT8 quantized version."""
        if not self.model_dir:
            return None
        
        # Prefer INT8 quantized version
        int8_path = self.model_dir / f"{self.model_name}_int8.onnx"
        if int8_path.exists():
            return int8_path
        
        # Fall back to original
        onnx_path = self.model_dir / f"{self.model_name}.onnx"
        if onnx_path.exists():
            return onnx_path
        
        return None

    def load(self) -> bool:
        """Load ONNX model and tokenizer.
        
        Returns:
            True if loaded successfully
            
        Performance Notes:
            - Uses optimized_model_filepath to cache graph optimizations
            - First load: ~2-3s (optimizes graph, saves cache)
            - Subsequent loads: ~0.5-1s (loads pre-optimized graph)
            - Thread config tuned for Intel CPUs (MKL backend)
        """
        onnx_path = self._get_onnx_path()
        if not onnx_path:
            logger.warning(f"{self.name} detector disabled: ONNX model not found at {self.model_dir}")
            return False

        # Try standalone tokenizer first (fast, no transformers)
        tokenizer_json = self.model_dir / f"{self.model_name}.tokenizer.json"
        # Fallback to HuggingFace directory
        tokenizer_dir = self.model_dir / f"{self.model_name}_tokenizer"
        
        labels_path = self.model_dir / f"{self.model_name}.labels.json"

        try:
            import onnxruntime as ort
        except ImportError:
            logger.warning(f"{self.name}: onnxruntime not installed")
            return False

        try:
            import os
            
            sess_options = ort.SessionOptions()
            
            # === Graph Optimization ===
            # Enable all optimizations (constant folding, operator fusion, etc.)
            sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            
            # Cache optimized graph to disk - HUGE win for subsequent loads
            # First load: optimizes graph (~2s), saves to .ort_optimized
            # Later loads: skips optimization, loads cached graph (~0.5s)
            optimized_path = str(onnx_path) + ".ort_optimized"
            sess_options.optimized_model_filepath = optimized_path
            
            # === Thread Configuration (Intel MKL backend) ===
            # intra_op: threads for parallelism WITHIN operators (e.g., matmul)
            # inter_op: threads for running DIFFERENT operators in parallel
            # For BERT on desktop: 4 intra + 2 inter balances speed vs responsiveness
            cpu_count = os.cpu_count() or 4
            sess_options.intra_op_num_threads = min(4, cpu_count)
            sess_options.inter_op_num_threads = min(2, max(1, cpu_count // 4))
            
            # === Memory Optimization ===
            # Memory pattern: reuses buffers between operators (less allocation overhead)
            sess_options.enable_mem_pattern = True
            # Memory arena: pre-allocates memory pool (faster allocation, slight memory overhead)
            sess_options.enable_cpu_mem_arena = True
            
            # === Logging ===
            # Reduce logging overhead in production (3 = Error only)
            sess_options.log_severity_level = 3

            # === Create Session ===
            # Filter providers to only those available (avoids CUDA warning on CPU-only systems)
            available = set(ort.get_available_providers())
            requested = ['CUDAExecutionProvider', 'CPUExecutionProvider']
            providers = [p for p in requested if p in available]

            self._session = ort.InferenceSession(
                str(onnx_path),
                sess_options,
                providers=providers,
            )
            
            # Try loading standalone tokenizer (preferred)
            if tokenizer_json.exists():
                self._load_fast_tokenizer(tokenizer_json)
            elif tokenizer_dir.exists():
                self._load_hf_tokenizer(tokenizer_dir)
            else:
                logger.warning(f"{self.name}: No tokenizer found")
                return False
            
            # Load label mappings
            if labels_path.exists():
                with open(labels_path) as f:
                    label_data = json.load(f)
                    self._id2label = {int(k): v for k, v in label_data.get('id2label', {}).items()}
            
            # Check if we used cached optimized model
            if Path(optimized_path).exists():
                logger.info(f"{self.name}: Loaded from cached optimized model")
            else:
                logger.info(f"{self.name}: ONNX model loaded and optimized (cached for next time)")
            
            self._loaded = True
            return True

        except Exception as e:
            logger.error(f"{self.name}: Failed to load ONNX model: {e}")
            return False

    def _load_fast_tokenizer(self, tokenizer_path: Path) -> None:
        """Load standalone tokenizer.json (no transformers dependency)."""
        from tokenizers import Tokenizer
        
        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        
        # Configure truncation (for long texts) but NO padding
        # Dynamic length = much faster inference on short texts
        self._tokenizer.enable_truncation(max_length=self._max_length)
        self._tokenizer.no_padding()
        
        self._use_fast_tokenizer = True
        logger.info(f"{self.name}: Loaded fast tokenizer from {tokenizer_path}")

    def _load_hf_tokenizer(self, tokenizer_dir: Path) -> None:
        """Load HuggingFace tokenizer (fallback, requires transformers)."""
        try:
            from transformers import AutoTokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(str(tokenizer_dir))
            self._use_fast_tokenizer = False
            logger.info(f"{self.name}: Loaded HF tokenizer from {tokenizer_dir}")
        except ImportError:
            raise ImportError(
                f"No standalone tokenizer found at {tokenizer_dir.parent / (self.model_name + '.tokenizer.json')}. "
                "Either run export_tokenizers.py or install transformers."
            )

    def _tokenize(self, text: str) -> Tuple[np.ndarray, np.ndarray, List[Tuple[int, int]]]:
        """
        Tokenize text and return arrays ready for ONNX inference.
        
        Returns:
            (input_ids, attention_mask, offset_mapping)
        """
        if self._use_fast_tokenizer:
            # Fast tokenizer path (tokenizers library) - no padding, dynamic length
            encoded = self._tokenizer.encode(text)
            
            input_ids = np.array([encoded.ids], dtype=np.int64)
            attention_mask = np.array([encoded.attention_mask], dtype=np.int64)
            offset_mapping = encoded.offsets
            
            return input_ids, attention_mask, offset_mapping
        else:
            # HuggingFace tokenizer path (transformers) - no padding
            inputs = self._tokenizer(
                text,
                return_tensors="np",
                padding=False,  # No padding - dynamic length
                truncation=True,
                max_length=self._max_length,
                return_offsets_mapping=True,
            )
            
            offset_mapping = inputs.pop('offset_mapping')[0].tolist()
            offset_mapping = [(int(s), int(e)) for s, e in offset_mapping]
            
            return inputs['input_ids'], inputs['attention_mask'], offset_mapping

    # --- CHUNKING FOR LONG DOCUMENTS ---
    def _chunk_text(self, text: str) -> List[Tuple[int, str]]:
        """
        Split long text into overlapping chunks for processing.
        
        Uses sentence-aware boundaries to avoid splitting entities mid-word.
        Overlap ensures entities at chunk boundaries are captured.
        
        Args:
            text: Full input text
            
        Returns:
            List of (start_char_offset, chunk_text) tuples
        """
        if len(text) <= self.CHUNK_MAX_CHARS:
            return [(0, text)]
        
        chunks = []
        pos = 0
        text_len = len(text)
        
        while pos < text_len:
            # Calculate chunk end
            chunk_end = min(pos + self.CHUNK_MAX_CHARS, text_len)
            
            # If not at the end, try to break at a good boundary
            if chunk_end < text_len:
                chunk_end = self._find_chunk_boundary(text, pos, chunk_end)
            
            chunk_text = text[pos:chunk_end]
            chunks.append((pos, chunk_text))
            
            # Move forward, but ensure overlap
            next_pos = chunk_end - self.CHUNK_MIN_OVERLAP
            
            # Ensure we make progress (avoid infinite loop)
            if next_pos <= pos:
                next_pos = pos + self.CHUNK_STRIDE
            
            pos = next_pos
            
            # Safety: if we've gone past the end, stop
            if pos >= text_len:
                break
        
        logger.debug(f"{self.name}: Split {text_len} chars into {len(chunks)} chunks")
        return chunks

    def _find_chunk_boundary(self, text: str, start: int, end: int) -> int:
        """
        Find a good boundary point for chunk splitting.
        
        Prefers (in order): paragraph break, sentence end, word boundary.
        Searches backwards from end within the overlap zone.
        
        Args:
            text: Full text
            start: Chunk start position
            end: Initial chunk end position
            
        Returns:
            Adjusted end position at a natural boundary
        """
        # Minimum position to search (don't go too far back)
        min_pos = start + self.CHUNK_STRIDE
        
        # Search zone: from min_pos to end
        search_text = text[min_pos:end]
        
        # Try paragraph boundary first (strongest)
        for sep in ['\n\n', '\r\n\r\n']:
            idx = search_text.rfind(sep)
            if idx != -1:
                return min_pos + idx + len(sep)
        
        # Try sentence boundary
        for sep in ['. ', '.\n', '? ', '?\n', '! ', '!\n']:
            idx = search_text.rfind(sep)
            if idx != -1:
                return min_pos + idx + len(sep)
        
        # Try line boundary
        idx = search_text.rfind('\n')
        if idx != -1:
            return min_pos + idx + 1
        
        # Try word boundary (space)
        idx = search_text.rfind(' ')
        if idx != -1:
            return min_pos + idx + 1
        
        # No good boundary found, use original end
        return end

    def _dedupe_spans(self, spans: List[Span], full_text: str = "") -> List[Span]:
        """
        Remove duplicate/overlapping spans from chunk boundaries.
        
        When spans overlap (from chunk overlap regions), keeps the one
        with highest confidence. Also merges adjacent same-type spans.
        
        Args:
            spans: All spans from all chunks (with adjusted offsets)
            full_text: Original full text for re-slicing merged spans
            
        Returns:
            Deduplicated list of spans
        """
        if not spans:
            return []
        
        # Sort by start position, then by confidence (descending) for ties
        spans = sorted(spans, key=lambda s: (s.start, -s.confidence))
        
        result = []
        for span in spans:
            if not result:
                result.append(span)
                continue
            
            last = result[-1]
            
            # Check for overlap
            if span.start < last.end:
                # Overlapping spans
                if span.entity_type == last.entity_type:
                    # Same type - merge or keep higher confidence
                    if span.end > last.end:
                        # Span extends further - merge
                        merged_start = last.start
                        merged_end = span.end
                        # Re-slice from full text to get correct merged text
                        if full_text and merged_end <= len(full_text):
                            merged_text = full_text[merged_start:merged_end]
                        else:
                            # Fallback: use the span with higher confidence
                            merged_text = span.text if span.confidence > last.confidence else last.text
                        merged = Span(
                            start=merged_start,
                            end=merged_end,
                            text=merged_text,
                            entity_type=last.entity_type,
                            confidence=max(last.confidence, span.confidence),
                            detector=last.detector,
                            tier=last.tier,
                        )
                        result[-1] = merged
                    elif span.confidence > last.confidence:
                        # Same coverage but higher confidence
                        result[-1] = span
                    # Otherwise keep last (higher or equal confidence)
                else:
                    # Different types overlapping - keep higher confidence
                    if span.confidence > last.confidence:
                        result[-1] = span
            else:
                # No overlap - add span
                result.append(span)
        
        return result

    def _process_chunk(
        self,
        chunk_start: int,
        chunk_text: str,
        full_text: str,
        full_text_len: int
    ) -> List[Span]:
        """
        Process a single chunk and return spans with adjusted offsets.

        This is a helper for parallel chunk processing.

        Args:
            chunk_start: Offset of chunk in original text
            chunk_text: The chunk text to process
            full_text: Original full text (for extracting span text)
            full_text_len: Length of original text

        Returns:
            List of spans with offsets adjusted to original text positions
        """
        chunk_spans = self._detect_single(chunk_text)
        adjusted_spans = []

        for span in chunk_spans:
            adj_start = span.start + chunk_start
            adj_end = span.end + chunk_start

            # Clamp to full text bounds
            adj_start = max(0, min(adj_start, full_text_len))
            adj_end = max(0, min(adj_end, full_text_len))

            # Skip invalid spans
            if adj_start >= adj_end:
                continue

            adjusted_span = Span(
                start=adj_start,
                end=adj_end,
                text=full_text[adj_start:adj_end],
                entity_type=span.entity_type,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
            )
            adjusted_spans.append(adjusted_span)

        return adjusted_spans

    # --- MAIN DETECTION ---
    def detect(self, text: str) -> List[Span]:
        """Run NER inference using ONNX runtime.

        Handles long documents via chunking with overlap.
        Uses parallel processing for multiple chunks.

        Returns list of Spans with detected entities.

        Raises:
            ValueError: If text contains null bytes
        """
        if not self._loaded or not self._session:
            return []

        # Reject null bytes - they can cause issues with tokenizers and indicate corrupt input
        if '\x00' in text:
            raise ValueError("Text contains null bytes which are not allowed")

        try:
            # Fast path for short texts (most common case)
            if len(text) <= self.CHUNK_MAX_CHARS:
                return self._detect_single(text)

            # Long text: chunk and process in parallel
            chunks = self._chunk_text(text)
            full_text_len = len(text)

            # Use parallel processing for multiple chunks
            # Limit workers based on chunk count and CPU
            num_workers = min(
                self.CHUNK_PARALLEL_WORKERS,
                len(chunks),
                os.cpu_count() or 4
            )

            all_spans = []

            if num_workers > 1 and len(chunks) > 1:
                # Parallel processing
                with ThreadPoolExecutor(max_workers=num_workers) as executor:
                    # Submit all chunk processing tasks
                    futures = {
                        executor.submit(
                            self._process_chunk,
                            chunk_start, chunk_text, text, full_text_len
                        ): chunk_start
                        for chunk_start, chunk_text in chunks
                    }

                    # Collect results as they complete
                    for future in as_completed(futures):
                        try:
                            chunk_spans = future.result()
                            all_spans.extend(chunk_spans)
                        except Exception as e:
                            chunk_start = futures[future]
                            logger.warning(f"{self.name}: Chunk at {chunk_start} failed: {e}")
            else:
                # Sequential fallback (single chunk or single worker)
                for chunk_start, chunk_text in chunks:
                    chunk_spans = self._process_chunk(
                        chunk_start, chunk_text, text, full_text_len
                    )
                    all_spans.extend(chunk_spans)

            # Deduplicate spans from overlapping regions
            return self._dedupe_spans(all_spans, full_text=text)

        except Exception as e:
            logger.error(f"{self.name}: Inference failed: {e}")
            return []

    def _detect_single(self, text: str) -> List[Span]:
        """
        Run inference on a single chunk of text.
        
        This is the core inference logic, separated for chunking support.
        
        Args:
            text: Text to process (must be <= CHUNK_MAX_CHARS)
            
        Returns:
            List of spans (offsets relative to input text)
        """
        if not text.strip():
            return []
        
        # Tokenize
        input_ids, attention_mask, offset_mapping = self._tokenize(text)
        
        # Run inference
        outputs = self._session.run(
            None,
            {
                'input_ids': input_ids,
                'attention_mask': attention_mask,
            }
        )
        
        logits = outputs[0][0]  # [sequence_length, num_labels]
        predictions = np.argmax(logits, axis=-1)
        confidences = np.max(self._softmax(logits), axis=-1)
        
        # Convert predictions to spans
        spans = self._predictions_to_spans(
            text, predictions, confidences, offset_mapping
        )
        
        return spans

    def _softmax(self, x: np.ndarray) -> np.ndarray:
        """Compute softmax values."""
        exp_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
        return exp_x / np.sum(exp_x, axis=-1, keepdims=True)

    def _predictions_to_spans(
        self,
        text: str,
        predictions: np.ndarray,
        confidences: np.ndarray,
        offset_mapping: List[Tuple[int, int]],
    ) -> List[Span]:
        """Convert token predictions to character-level spans.

        Handles BIO tagging and merges consecutive same-entity tokens.
        """
        spans = []
        current_entity = None
        current_start = None
        current_end = None
        current_confidence = 0.0
        text_len = len(text)

        # Pre-compute word boundaries once for O(log n) lookups instead of O(word_len) per entity
        word_starts, word_ends = build_word_boundaries(text)
        
        for idx, (pred, conf) in enumerate(zip(predictions, confidences)):
            # Get offset for this token
            if idx >= len(offset_mapping):
                break
            start, end = offset_mapping[idx]
            
            # Skip special tokens (offset 0,0)
            if start == end == 0:
                continue
            
            # Validate offsets are within text bounds
            if start < 0 or end > text_len or start >= end:
                continue
            
            label = self._id2label.get(int(pred), "O")
            
            # Parse BIO tag
            if label.startswith("B-"):
                # Save previous entity if exists
                if current_entity:
                    span = self._create_span(
                        text, current_start, current_end,
                        current_entity, current_confidence,
                        word_starts, word_ends
                    )
                    if span:
                        spans.append(span)

                # Start new entity
                current_entity = label[2:]  # Remove B-
                current_start = int(start)
                current_end = int(end)
                current_confidence = float(conf)

            elif label.startswith("I-") and current_entity:
                # Continue current entity (if same type)
                entity_type = label[2:]
                if entity_type == current_entity:
                    current_end = int(end)
                    current_confidence = min(current_confidence, float(conf))
                else:
                    # Different type - save and start new
                    span = self._create_span(
                        text, current_start, current_end,
                        current_entity, current_confidence,
                        word_starts, word_ends
                    )
                    if span:
                        spans.append(span)
                    current_entity = entity_type
                    current_start = int(start)
                    current_end = int(end)
                    current_confidence = float(conf)

            elif label != "O" and not label.startswith(("B-", "I-")):
                # Non-BIO label (e.g., just "PATIENT")
                if current_entity == label:
                    # Continue
                    current_end = int(end)
                    current_confidence = min(current_confidence, float(conf))
                else:
                    # Save previous and start new
                    if current_entity:
                        span = self._create_span(
                            text, current_start, current_end,
                            current_entity, current_confidence,
                            word_starts, word_ends
                        )
                        if span:
                            spans.append(span)
                    current_entity = label
                    current_start = int(start)
                    current_end = int(end)
                    current_confidence = float(conf)
            else:
                # O label - save current entity if exists
                if current_entity:
                    span = self._create_span(
                        text, current_start, current_end,
                        current_entity, current_confidence,
                        word_starts, word_ends
                    )
                    if span:
                        spans.append(span)
                    current_entity = None

        # Don't forget last entity
        if current_entity:
            span = self._create_span(
                text, current_start, current_end,
                current_entity, current_confidence,
                word_starts, word_ends
            )
            if span:
                spans.append(span)

        return spans

    def _trim_name_span_end(self, text: str, start: int, end: int) -> int:
        """Trim NAME span end at non-name words.

        ML models sometimes extend NAME spans to include following words like
        "appears", "is", "to", etc. This trims those off.

        A word is trimmed if:
        1. It's in NON_NAME_WORDS (case-insensitive), OR
        2. It's lowercase, not a name connector, and > 5 chars

        Returns new end position.
        """
        span_text = text[start:end]
        words = span_text.split()

        if len(words) <= 1:
            return end  # Single word - keep as-is

        # Work backwards, trimming non-name words
        while len(words) > 1:
            last_word = words[-1].rstrip('.,;:!?')  # Strip trailing punct
            last_lower = last_word.lower()

            # Check if this word should be trimmed
            should_trim = False

            # Rule 1: Explicit non-name words
            if last_lower in NON_NAME_WORDS:
                should_trim = True
            # Rule 2: Lowercase, not a connector, and > 5 chars
            elif (last_word.islower() and
                  last_lower not in NAME_CONNECTORS and
                  len(last_word) > 5):
                should_trim = True

            if should_trim:
                words.pop()
            else:
                break

        # Recalculate end position by finding where the last kept word ends
        # in the original text (don't use join() which normalizes spacing)
        last_word = words[-1]
        # Find the last occurrence of the last word in the span text
        # Then find the end of that word (include any trailing punctuation that was part of it)
        search_start = 0
        for i, word in enumerate(words[:-1]):
            # Skip past earlier words to find the last one
            pos = span_text.find(word, search_start)
            if pos != -1:
                search_start = pos + len(word)

        # Find where the last word appears (after any previous words)
        last_word_pos = span_text.find(last_word, search_start)
        if last_word_pos == -1:
            # Fallback: use conservative estimate
            last_word_pos = span_text.rfind(last_word)

        if last_word_pos != -1:
            # Find end of this word (continue while not whitespace)
            word_end = last_word_pos + len(last_word)
            # Include any trailing punctuation that's attached (but not if it's whitespace)
            while word_end < len(span_text) and span_text[word_end] in '.,;:!?\'"-)':
                word_end += 1
            return start + word_end
        else:
            # Fallback: original behavior
            new_text = ' '.join(words)
            return start + len(new_text)

    def _create_span(
        self,
        text: str,
        start: int,
        end: int,
        entity_type: str,
        confidence: float,
        word_starts: List[int] = None,
        word_ends: List[int] = None,
    ) -> Optional[Span]:
        """Create a Span with canonical entity type.

        Expands span to word boundaries to prevent partial PHI leaks
        like "J[NAME_1]rner" instead of "[NAME_1]".

        Args:
            word_starts, word_ends: Pre-computed word boundaries for O(log n) expansion.
                If not provided, falls back to O(word_length) character iteration.

        Returns None if the span is invalid after processing.
        """
        text_len = len(text)

        # Clamp initial values to text bounds
        start = max(0, min(start, text_len))
        end = max(0, min(end, text_len))

        if start >= end:
            return None

        # Expand to word boundaries
        if word_starts is not None and word_ends is not None:
            # Use pre-computed boundaries for O(log n) lookup
            start, end = expand_to_word_boundary(start, end, word_starts, word_ends, text_len)
        else:
            # Fallback to O(word_length) character iteration
            while start > 0 and not text[start - 1].isspace():
                start -= 1
            while end < text_len and not text[end].isspace():
                end += 1

        # Final bounds check (should be unnecessary but safe)
        start = max(0, start)
        end = min(text_len, end)

        if start >= end:
            return None

        # Trim NAME spans at non-name words (defense layer 1)
        if entity_type == "NAME" or entity_type.startswith("NAME_"):
            end = self._trim_name_span_end(text, start, end)
            if start >= end:
                return None

        # Filter product codes falsely detected as MRN/ID (defense layer 2)
        # "SKU-123-45-6789" looks like an ID but is a product code
        if entity_type in ("ID", "MRN"):
            span_text = text[start:end]
            first_part = span_text.split('-')[0].split('_')[0].split('#')[0].lower()
            if first_part in PRODUCT_CODE_PREFIXES:
                return None

        # Map to canonical type
        # Priority: B-{type} (IOB format) > raw type > fallback to original
        canonical_type = self.label_map.get(f"B-{entity_type}")
        if canonical_type is None:
            canonical_type = self.label_map.get(entity_type, entity_type)
        
        return Span(
            start=start,
            end=end,
            text=text[start:end],
            entity_type=canonical_type,
            confidence=confidence,
            detector=self.name,
            tier=self.tier,
        )


class PHIBertONNXDetector(ONNXDetector):
    """Stanford Clinical PHI-BERT detector (ONNX-only, no PyTorch)."""

    name = "phi_bert_onnx"
    label_map = PHI_BERT_LABELS

    def __init__(self, model_dir: Optional[Path] = None):
        super().__init__(model_dir, model_name="phi_bert")
        if model_dir:
            self.load()


class PIIBertONNXDetector(ONNXDetector):
    """Custom PII-BERT detector (ONNX-only, no PyTorch)."""

    name = "pii_bert_onnx"
    label_map = PII_BERT_LABELS

    def __init__(self, model_dir: Optional[Path] = None):
        super().__init__(model_dir, model_name="pii_bert")
        if model_dir:
            self.load()
