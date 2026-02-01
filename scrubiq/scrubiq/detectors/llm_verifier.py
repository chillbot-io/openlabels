"""LLM-based verification for PII/PHI candidates.

Uses a local LLM (via Ollama) to verify candidates detected by other detectors.
This improves precision by filtering false positives while preserving recall.

Supported models (Apache 2.0 / MIT licensed):
- phi3:mini (MIT) - Microsoft Phi-3 Mini, 3.8B params, fast
- qwen2.5:3b (Apache 2.0) - Alibaba Qwen 2.5, good multilingual
- qwen2.5:7b (Apache 2.0) - Larger Qwen for better accuracy

Architecture:
    [Detectors] -> Candidates -> [LLM Verifier] -> Verified PII

The verifier asks the LLM: "Is this actually PII in this context?"
This catches false positives like:
- "Apple" detected as NAME (but it's the company)
- "Jordan" detected as NAME (but it's the country)
- "Will" detected as NAME (but it's a verb)

DEV/PROD PARITY CONSIDERATIONS
==============================

The LLM verifier introduces potential inconsistencies between development and
production environments. Address these to ensure reproducible behavior:

1. MODEL VERSION PINNING
   - Always specify exact model tags: "qwen2.5:3b-instruct-q4_0" not "qwen2.5:3b"
   - Ollama models are updated frequently; "latest" changes behavior
   - Document the exact model SHA256 hash in your deployment config
   - Use `ollama list` to see installed versions

2. FALLBACK BEHAVIOR
   - When Ollama is unavailable, the verifier is bypassed (all spans pass through)
   - This means dev (Ollama running) may filter more than prod (Ollama down)
   - Solution A: Require Ollama in all environments (preferred)
   - Solution B: Disable LLM verification in prod (enable_llm_verification=False)
   - NEVER rely on LLM being "sometimes available" - inconsistent filtering

3. HARDWARE DIFFERENCES
   - Inference time varies 10-100x between CPU/GPU
   - Dev MacBook vs Prod Linux server may timeout differently
   - Tune `timeout` parameter per environment if needed
   - Consider VERIFY_ENTITY_TYPES = {} (disabled) for CPU-only prod

4. QUANTIZATION EFFECTS
   - q4_0, q5_1, q8_0 produce slightly different outputs
   - Test precision/recall with your exact production quantization
   - Document the quantization level alongside model version

5. TEMPERATURE AND SAMPLING
   - The verifier uses temperature=0 for determinism
   - Ensure Ollama seed is set if using non-zero temperature
   - Different GPU drivers may produce different sampling results

6. MONITORING RECOMMENDATIONS
   - Log LLM verification accept/reject rates
   - Alert if verification rate changes significantly (model drift)
   - Track p95 latency - spikes indicate resource contention
   - Include is_available() status in health checks

7. GRACEFUL DEGRADATION
   - Current behavior: LLM unavailable → all candidates pass through
   - This preserves recall (no missed PHI) at cost of precision (more FPs)
   - For high-security deployments, consider failing closed instead:
     * Set config.require_llm_verification = True
     * Return error if Ollama is down rather than degraded results

8. TESTING STRATEGY
   - Unit tests should mock Ollama responses for speed
   - Integration tests should use real Ollama with pinned model
   - Golden file tests should include LLM verification output
   - Run nightly tests against production-identical Ollama config

CURRENT STATUS
==============
VERIFY_ENTITY_TYPES is currently empty (LLM verification disabled).
This is intentional - pattern-based filtering achieves similar precision
with 3x lower latency. Re-enable by adding types to VERIFY_ENTITY_TYPES
if your use case has many ambiguous names/addresses.
"""

import json
import logging
import time
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple
import urllib.request
import urllib.error

from ..types import Span

logger = logging.getLogger(__name__)

# Default Ollama endpoint
DEFAULT_OLLAMA_URL = "http://localhost:11434"

# Default model - Qwen2.5:3b chosen for:
# - Apache 2.0 license (user requirement)
# - Excellent multilingual support (AI4Privacy has 6 languages)
# - Reliable JSON output formatting
# - Fast inference at 3B parameters
DEFAULT_MODEL = "qwen2.5:3b"

# Fallback models in order of preference
FALLBACK_MODELS = [
    "qwen2.5:3b",     # Apache 2.0, best multilingual, reliable JSON
    "qwen2.5:7b",     # Apache 2.0, better accuracy if resources allow
    "phi3:mini",      # MIT license, English-focused fallback
]

# Entity types that benefit most from LLM verification
# Based on benchmark data: patterns + deny lists are more effective than LLM
# LLM adds 3x latency with marginal gains - disabled in favor of patterns
# To re-enable, add types like: "NAME", "PERSON", "USERNAME", "ADDRESS"
VERIFY_ENTITY_TYPES: set = set()  # Disabled - using patterns/deny lists instead

# All other types pass through without LLM verification:
# - SSN, CREDIT_CARD, etc. are checksum-validated (high precision)
# - EMAIL, PHONE, URL have distinct patterns (high precision)
# - ADDRESS, DOB, etc. have acceptable precision


@dataclass
class VerificationResult:
    """Result of LLM verification for a single span."""
    span: Span
    verified: bool
    llm_confidence: float  # LLM's confidence that this is real PII
    reasoning: str  # Brief explanation from LLM


class LLMVerifier:
    """
    Verifies PII/PHI candidates using a local LLM via Ollama.

    The verifier sends candidates with context to the LLM and asks
    whether each is actually PII in the given context.

    Usage:
        verifier = LLMVerifier(model="phi3:mini")
        if verifier.is_available():
            verified_spans = verifier.verify(text, candidate_spans)
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        timeout: float = 30.0,
        min_confidence: float = 0.6,
        batch_size: int = 1,  # Single item verification for 3B models (more accurate)
        context_window: int = 75,  # Chars on each side of entity
    ):
        """
        Initialize the LLM verifier.

        Args:
            model: Ollama model name (phi3:mini, qwen2.5:3b, etc.)
            ollama_url: Ollama API endpoint
            timeout: Request timeout in seconds
            min_confidence: Minimum LLM confidence to keep a span
            batch_size: Max candidates per LLM request (1 recommended for 3B models)
            context_window: Characters of context on each side of entity
        """
        self.model = model
        self.ollama_url = ollama_url.rstrip('/')
        self.timeout = timeout
        self.min_confidence = min_confidence
        self.batch_size = batch_size
        self.context_window = context_window
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if Ollama is running and model is available."""
        if self._available is not None:
            return self._available

        try:
            # Check Ollama is running
            req = urllib.request.Request(
                f"{self.ollama_url}/api/tags",
                method="GET"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                models = [m.get("name", "") for m in data.get("models", [])]

                # Check if our model is available
                model_base = self.model.split(":")[0]
                self._available = any(model_base in m for m in models)

                if not self._available:
                    logger.warning(
                        f"LLM Verifier: Model {self.model} not found. "
                        f"Available: {models}. Run: ollama pull {self.model}"
                    )
                else:
                    logger.info(f"LLM Verifier: Using {self.model}")

                return self._available

        except (urllib.error.URLError, TimeoutError) as e:
            logger.warning(f"LLM Verifier: Ollama not available at {self.ollama_url}: {e}")
            self._available = False
            return False

    def _get_context(self, text: str, span: Span, window: Optional[int] = None) -> str:
        """Extract context around a span."""
        window = window or self.context_window
        start = max(0, span.start - window)
        end = min(len(text), span.end + window)

        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""

        return f"{prefix}{text[start:end]}{suffix}"

    def _build_messages(self, text: str, span: Span) -> List[Dict[str, str]]:
        """Build chat messages with few-shot examples (proven better for small LLMs)."""
        context = self._get_context(text, span)
        entity_type = span.entity_type.upper()

        # Few-shot prompting with examples - much better for 3B models
        if entity_type in ("NAME", "PERSON", "PER"):
            system_msg = "Classify if text is a person's name. Respond with JSON: {\"answer\": \"YES\"} or {\"answer\": \"NO\"}"
            user_msg = (
                "Examples:\n"
                "\"Dr. Sarah Chen\" in \"Contact Dr. Sarah Chen at...\" → {\"answer\": \"YES\"}\n"
                "\"Lewis-Osborne\" in \"...contract with Lewis-Osborne Inc...\" → {\"answer\": \"NO\"} (company)\n"
                "\"Jordan\" in \"The country of Jordan has...\" → {\"answer\": \"NO\"} (place)\n"
                "\"Will\" in \"This will ensure...\" → {\"answer\": \"NO\"} (common word)\n"
                "\"Walker-Kay\" in \"...employed by Walker-Kay Ltd...\" → {\"answer\": \"NO\"} (company)\n"
                "\"Maria Garcia\" in \"Patient Maria Garcia arrived...\" → {\"answer\": \"YES\"}\n\n"
                f"Now classify:\n"
                f"\"{span.text}\" in \"{context}\""
            )
        elif entity_type == "USERNAME":
            system_msg = "Classify if text is a username/handle. Respond with JSON: {\"answer\": \"YES\"} or {\"answer\": \"NO\"}"
            user_msg = (
                "Examples:\n"
                "\"john_doe92\" in \"Login as john_doe92...\" → {\"answer\": \"YES\"}\n"
                "\"@mike_smith\" in \"Contact @mike_smith on...\" → {\"answer\": \"YES\"}\n"
                "\"has\" in \"Your account has been...\" → {\"answer\": \"NO\"} (common word)\n"
                "\"number\" in \"Enter account number:...\" → {\"answer\": \"NO\"} (common word)\n"
                "\"admin\" in \"Contact admin for...\" → {\"answer\": \"NO\"} (generic role)\n"
                "\"user2847\" in \"Created by user2847...\" → {\"answer\": \"YES\"}\n\n"
                f"Now classify:\n"
                f"\"{span.text}\" in \"{context}\""
            )
        elif entity_type == "ADDRESS":
            system_msg = "Classify if text is a street address. Respond with JSON: {\"answer\": \"YES\"} or {\"answer\": \"NO\"}"
            user_msg = (
                "Examples:\n"
                "\"123 Main Street\" in \"Located at 123 Main Street...\" → {\"answer\": \"YES\"}\n"
                "\"New York, NY 10001\" in \"Ship to New York, NY 10001...\" → {\"answer\": \"YES\"}\n"
                "\"Maisonette\" in \"...type: Maisonette, bedrooms: 3...\" → {\"answer\": \"NO\"} (building type)\n"
                "\"Operations\" in \"The Operations department...\" → {\"answer\": \"NO\"} (department name)\n"
                "\"Suite 400\" in \"Office at Suite 400...\" → {\"answer\": \"YES\"}\n"
                "\"Building\" in \"Enter the Building via...\" → {\"answer\": \"NO\"} (generic word)\n\n"
                f"Now classify:\n"
                f"\"{span.text}\" in \"{context}\""
            )
        else:
            # Generic fallback with example structure
            system_msg = f"Classify if text is {entity_type}. Respond with JSON: {{\"answer\": \"YES\"}} or {{\"answer\": \"NO\"}}"
            user_msg = (
                f"Is \"{span.text}\" a valid {entity_type}?\n"
                f"Context: {context}"
            )

        return [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg}
        ]

    def _call_ollama(self, messages: List[Dict[str, str]]) -> Optional[Dict]:
        """Make a request to Ollama Chat API with JSON mode (Qwen2.5 best practice)."""
        try:
            payload = json.dumps({
                "model": self.model,
                "messages": messages,
                "stream": False,
                "format": "json",  # Forces JSON output - key for Qwen2.5
                "options": {
                    "temperature": 0,  # Deterministic for classification
                    "num_predict": 64,  # Only need short response
                }
            }).encode()

            req = urllib.request.Request(
                f"{self.ollama_url}/api/chat",  # Chat API instead of generate
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            start = time.time()
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
                elapsed = time.time() - start
                logger.debug(f"LLM Verifier: Response in {elapsed:.2f}s")
                return data

        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            logger.error(f"LLM Verifier: Ollama request failed: {e}")
            return None

    def _parse_response(self, response: Dict, num_spans: int = 1) -> List[Tuple[bool, float, str]]:
        """Parse LLM response into verification results.

        Handles both chat API format and legacy generate API format.
        Optimized for JSON mode output from Qwen2.5.
        """
        import re
        results = []

        # Chat API returns message.content, generate API returns response
        if "message" in response:
            text = response.get("message", {}).get("content", "")
        else:
            text = response.get("response", "")

        # With format: "json", Qwen2.5 returns clean JSON like {"answer": "YES"}
        try:
            # Handle cases where LLM wraps JSON in markdown code blocks
            json_text = text.strip()
            if "```json" in json_text:
                json_text = json_text.split("```json")[1].split("```")[0]
            elif "```" in json_text:
                json_text = json_text.split("```")[1].split("```")[0]

            data = json.loads(json_text.strip())

            # New simple format: {"answer": "YES"} or {"answer": "NO"}
            if "answer" in data:
                answer = str(data.get("answer", "")).upper()
                verified = answer == "YES"
                confidence = 0.9 if verified else 0.9  # High confidence with JSON mode
                results.append((verified, confidence, "json_parsed"))
                logger.debug(f"LLM Verifier: Parsed answer={answer} via JSON")

            # Legacy batch format: {"results": [...]}
            elif "results" in data:
                llm_results = data.get("results", [])
                for item in llm_results:
                    verdict = item.get("verdict", "").upper()
                    confidence = float(item.get("confidence", 0.5))
                    reason = item.get("reason", "")
                    verified = verdict == "YES"
                    results.append((verified, confidence, reason))
                if results:
                    logger.debug(f"LLM Verifier: Parsed {len(results)} results via JSON")

        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            logger.debug(f"LLM Verifier: JSON parse failed, trying regex: {e}")

        # Fallback: Regex for "answer": "YES" pattern
        if not results:
            answer_pattern = r'"answer"\s*:\s*"(YES|NO)"'
            matches = re.findall(answer_pattern, text, re.IGNORECASE)
            if matches:
                for answer in matches:
                    verified = answer.upper() == "YES"
                    results.append((verified, 0.8, "regex_parsed"))
                logger.debug(f"LLM Verifier: Parsed {len(results)} results via regex")

        # Fallback: Look for standalone YES/NO
        if not results:
            text_upper = text.upper().strip()
            if "YES" in text_upper and "NO" not in text_upper:
                results.append((True, 0.7, "text_yes"))
            elif "NO" in text_upper and "YES" not in text_upper:
                results.append((False, 0.7, "text_no"))
            if results:
                logger.debug(f"LLM Verifier: Parsed via text matching")

        # If still no results, accept all (preserve recall)
        if not results:
            logger.warning(f"LLM Verifier: Could not parse response: {text[:100]}")
            results = [(True, 0.5, "parse_error")] * num_spans

        # Pad if we got fewer results than expected
        while len(results) < num_spans:
            results.append((True, 0.5, "missing_result"))

        return results[:num_spans]

    def verify(
        self,
        text: str,
        spans: List[Span],
        skip_high_confidence: bool = True,
    ) -> List[Span]:
        """
        Verify candidate spans using LLM.

        Args:
            text: Original text
            spans: Candidate spans to verify
            skip_high_confidence: Skip verification for checksum-validated entities

        Returns:
            List of verified spans (false positives filtered out)
        """
        if not spans:
            return spans

        if not self.is_available():
            logger.warning("LLM Verifier: Not available, returning all candidates")
            return spans

        # Separate spans into those needing verification and those to skip
        # Only verify high-FP types (NAME, USERNAME) - everything else passes through
        to_verify: List[Span] = []
        verified: List[Span] = []

        for span in spans:
            # Only verify types known to have high false positive rates
            if span.entity_type in VERIFY_ENTITY_TYPES:
                # But skip if already very high confidence from structured extraction
                if span.detector == "structured" and span.confidence >= 0.95:
                    verified.append(span)
                else:
                    to_verify.append(span)
            else:
                # All other types pass through without LLM verification
                verified.append(span)

        if not to_verify:
            logger.debug("LLM Verifier: No candidates need verification")
            return verified

        logger.info(f"LLM Verifier: Verifying {len(to_verify)} candidates...")
        rejected_count = 0

        # Single-item verification (more accurate for 3B models like Qwen2.5:3b)
        for span in to_verify:
            messages = self._build_messages(text, span)
            response = self._call_ollama(messages)

            if response is None:
                # On failure, keep candidate (preserve recall)
                verified.append(span)
                continue

            results = self._parse_response(response, 1)
            is_verified, llm_conf, reason = results[0]

            if is_verified and llm_conf >= self.min_confidence:
                # Boost confidence based on LLM agreement
                if llm_conf > 0.8:
                    span.confidence = min(0.99, span.confidence + 0.1)
                verified.append(span)
                logger.debug(
                    f"LLM Verifier: KEPT '{span.text}' ({span.entity_type}) "
                    f"- {reason}"
                )
            else:
                rejected_count += 1
                logger.info(
                    f"LLM Verifier: REJECTED '{span.text}' ({span.entity_type}) "
                    f"- {reason}"
                )

        logger.info(
            f"LLM Verifier: Kept {len(verified)}/{len(spans)} "
            f"({rejected_count} false positives filtered)"
        )

        return verified

    def verify_single(self, text: str, span: Span) -> VerificationResult:
        """
        Verify a single span (for debugging/inspection).

        Returns detailed verification result including LLM reasoning.
        """
        if not self.is_available():
            return VerificationResult(
                span=span,
                verified=True,
                llm_confidence=0.5,
                reasoning="LLM not available"
            )

        messages = self._build_messages(text, span)
        response = self._call_ollama(messages)

        if response is None:
            return VerificationResult(
                span=span,
                verified=True,
                llm_confidence=0.5,
                reasoning="LLM request failed"
            )

        results = self._parse_response(response, 1)
        is_verified, llm_conf, reason = results[0]

        return VerificationResult(
            span=span,
            verified=is_verified,
            llm_confidence=llm_conf,
            reasoning=reason
        )


def create_verifier(
    model: Optional[str] = None,
    ollama_url: Optional[str] = None,
) -> LLMVerifier:
    """
    Create an LLM verifier with auto-detected settings.

    Tries to find an available model in order of preference.
    """
    url = ollama_url or DEFAULT_OLLAMA_URL

    if model:
        return LLMVerifier(model=model, ollama_url=url)

    # Try fallback models in order of preference
    for candidate in FALLBACK_MODELS:
        verifier = LLMVerifier(model=candidate, ollama_url=url)
        if verifier.is_available():
            return verifier

    # Return default (will report unavailable)
    return LLMVerifier(model=DEFAULT_MODEL, ollama_url=url)
