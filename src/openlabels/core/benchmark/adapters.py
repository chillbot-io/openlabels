"""Dataset adapters for external PII benchmark datasets.

Converts various PII-annotated dataset formats into OpenLabels
``BenchmarkSample`` objects for evaluation against the detection pipeline.

Supported datasets:
- **Gretel PII-Masking EN v1**: 40+ PII/PHI types across 45 domains
- **Gretel Synthetic PII Finance Multilingual**: 29 PII types in financial documents
- **Generic JSONL**: Any dataset following the {text, entities} convention

Usage:
    from openlabels.core.benchmark.adapters import load_gretel_pii, load_gretel_finance
    samples = load_gretel_pii("path/to/gretel_pii_test.jsonl", sample_size=1000)
    result = run_benchmark(samples=samples, config=config)
"""

from __future__ import annotations

import gzip
import json
import logging
import random
from pathlib import Path

from .dataset import BenchmarkSample, GoldSpan

logger = logging.getLogger(__name__)

# Full language name → ISO 639-1 code mapping for multilingual datasets.
# Gretel Finance uses full English names ("English", "Spanish", etc.).
_LANGUAGE_NAME_TO_CODE: dict[str, str] = {
    "english": "en",
    "spanish": "es",
    "french": "fr",
    "german": "de",
    "italian": "it",
    "portuguese": "pt",
    "dutch": "nl",
    "russian": "ru",
    "chinese": "zh",
    "japanese": "ja",
    "korean": "ko",
    "arabic": "ar",
    "hindi": "hi",
    "turkish": "tr",
    "polish": "pl",
    "swedish": "sv",
    "norwegian": "no",
    "danish": "da",
    "finnish": "fi",
    "czech": "cs",
    "romanian": "ro",
    "hungarian": "hu",
    "greek": "el",
    "thai": "th",
    "vietnamese": "vi",
    "indonesian": "id",
    "malay": "ms",
    "tagalog": "tl",
    "ukrainian": "uk",
    "hebrew": "he",
    "persian": "fa",
    "bengali": "bn",
    "tamil": "ta",
    "catalan": "ca",
    "croatian": "hr",
    "slovak": "sk",
    "slovenian": "sl",
    "bulgarian": "bg",
    "serbian": "sr",
    "latvian": "lv",
    "lithuanian": "lt",
    "estonian": "et",
}


# ── Entity type mappings ────────────────────────────────────────────────
# Each dataset uses its own naming convention.  We map to OpenLabels types.

GRETEL_PII_TO_OPENLABELS: dict[str, str] = {
    # Names
    "first_name": "FIRSTNAME",
    "last_name": "LASTNAME",
    "name": "NAME",
    "full_name": "NAME",
    "middle_name": "MIDDLENAME",
    "prefix": "PREFIX",
    "suffix": "SUFFIX",
    "patient_name": "NAME",
    "doctor_name": "NAME",

    # Dates / Time
    "date": "DATE",
    "date_of_birth": "DATE_DOB",
    "dob": "DATE_DOB",
    "date_time": "DATETIME",
    "time": "TIME",

    # Age
    "age": "AGE",

    # Location
    "street_address": "ADDRESS",
    "address": "ADDRESS",
    "city": "CITY",
    "state": "STATE",
    "postcode": "ZIP",
    "zip_code": "ZIP",
    "zipcode": "ZIP",
    "country": "COUNTRY",
    "county": "COUNTY",
    "coordinate": "GPS_COORDINATE",
    "coordinates": "GPS_COORDINATE",

    # Contact
    "email": "EMAIL",
    "phone_number": "PHONE",
    "phone": "PHONE",
    "url": "URL",
    "user_name": "USERNAME",
    "username": "USERNAME",

    # Government IDs
    "ssn": "SSN",
    "social_security_number": "SSN",
    "driver_license": "DRIVER_LICENSE",
    "drivers_license": "DRIVER_LICENSE",
    "passport_number": "PASSPORT",
    "passport": "PASSPORT",
    "national_id": "STATE_ID",
    "tax_id": "TAX_ID",
    "tax_number": "TAX_ID",

    # Financial - PCI relevant
    "credit_card_number": "CREDIT_CARD",
    "credit_card": "CREDIT_CARD",
    "iban": "IBAN",
    "swift": "SWIFT_BIC",
    "bic": "SWIFT_BIC",
    "bank_routing_number": "BANK_ROUTING",
    "routing_number": "BANK_ROUTING",
    "account_number": "ACCOUNT_NUMBER",
    "bank_account": "ACCOUNT_NUMBER",
    "customer_id": "ACCOUNT_NUMBER",

    # Medical / PHI
    "medical_record_number": "MRN",
    "mrn": "MRN",
    "health_plan_beneficiary_number": "HEALTH_PLAN_ID",
    "health_plan_id": "HEALTH_PLAN_ID",
    "health_insurance_id": "HEALTH_PLAN_ID",
    "npi": "NPI",
    "medical_license": "MEDICAL_LICENSE",

    # Professional
    "company_name": "COMPANY",
    "company": "COMPANY",
    "employer": "EMPLOYER",
    "employee_id": "EMPLOYEE_ID",
    "job_title": "JOB_TITLE",

    # Network / Device
    "ipv4": "IP_ADDRESS",
    "ipv6": "IP_ADDRESS",
    "ip_address": "IP_ADDRESS",
    "mac_address": "MAC_ADDRESS",
    "device_identifier": "DEVICE_ID",
    "imei": "IMEI",

    # Vehicle
    "license_plate": "LICENSE_PLATE",
    "vehicle_identifier": "VIN",
    "vin": "VIN",

    # Secrets
    "password": "PASSWORD",
    "api_key": "API_KEY",
    "pin": "PASSWORD",

    # IDs / Certificates
    "unique_identifier": "UNIQUE_ID",
    "certificate_license_number": "CERTIFICATE_NUMBER",
    "biometric_identifier": "BIOMETRIC_ID",

    # Crypto
    "bitcoin_address": "BITCOIN_ADDRESS",
    "ethereum_address": "ETHEREUM_ADDRESS",
}

# Gretel Finance uses Faker-aligned names — mostly the same but a few differ
GRETEL_FINANCE_TO_OPENLABELS: dict[str, str] = {
    **GRETEL_PII_TO_OPENLABELS,
    # Finance-specific overrides / additions
    "aba": "BANK_ROUTING",
    "bban": "ACCOUNT_NUMBER",
    "credit_card_expire": None,  # Exclude - metadata, not PII
    "credit_card_security_code": None,  # Exclude - too generic
    "currency_code": None,  # Exclude
    "currency_name": None,  # Exclude
    "currency_symbol": None,  # Exclude
    "job": None,  # Exclude
    "text": None,  # Exclude - free text, not PII
    # Finance dataset uses slightly different label names
    "swift_bic_code": "SWIFT_BIC",
    "driver_license_number": "DRIVER_LICENSE",
    "local_latlng": "GPS_COORDINATE",
    "account_pin": "PASSWORD",
    "first_name": "FIRSTNAME",
    "last_name": "LASTNAME",
}


NEMOTRON_TO_OPENLABELS: dict[str, str | None] = {
    # Names
    "name": "NAME",
    "first_name": "FIRSTNAME",
    "last_name": "LASTNAME",

    # Dates / Time
    "date_of_birth": "DATE_DOB",
    "date_time": "DATETIME",
    "time": "TIME",

    # Location
    "address": "ADDRESS",
    "location": "ADDRESS",
    "city": "CITY",
    "state": "STATE",
    "country": "COUNTRY",
    "coordinate": "GPS_COORDINATE",
    "coordinates": "GPS_COORDINATE",

    # Contact
    "email": "EMAIL",
    "phone_number": "PHONE",
    "fax_number": "FAX",
    "url": "URL",
    "user_name": "USERNAME",

    # Government IDs
    "ssn": "SSN",
    "national_id": "STATE_ID",
    "tax_id": "TAX_ID",

    # Financial
    "credit_card_number": "CREDIT_CARD",
    "credit_debit_card": "CREDIT_CARD",
    "account_number": "ACCOUNT_NUMBER",
    "bank_routing_number": "BANK_ROUTING",
    "swift_bic": "SWIFT_BIC",
    "cvv": None,  # Exclude — metadata, not standalone PII
    "pin": "PASSWORD",

    # Medical / PHI
    "medical_record_number": "MRN",
    "health_plan_beneficiary_number": "HEALTH_PLAN_ID",
    "biometric_identifier": "BIOMETRIC_ID",

    # Professional — not PII in most frameworks (GDPR, CCPA, HIPAA).
    # Company names and job titles do not uniquely identify individuals.
    # Excluding from gold scoring (same as ai4privacy JOBTITLE/JOBTYPE).
    "company_name": None,
    "occupation": None,
    # Employee/customer IDs ARE identifiers → keep mapped.
    "employee_id": "EMPLOYEE_ID",
    "customer_id": "ACCOUNT_NUMBER",

    # Network / Device
    "ip_address": "IP_ADDRESS",
    "device_identifier": "DEVICE_ID",

    # Vehicle
    "license_plate": "LICENSE_PLATE",
    "vehicle_identifier": "VIN",

    # Secrets
    "password": "PASSWORD",
    "api_key": "API_KEY",
    "http_cookie": "API_KEY",

    # IDs / Certificates
    "unique_identifier": "UNIQUE_ID",
    "certificate_license_number": "CERTIFICATE_NUMBER",

    # Location (additional)
    "postcode": "ZIP",
    "postal_code": "ZIP",
    "zip_code": "ZIP",

    # Demographic / non-PII — exclude from scoring
    "gender": None,
    "race_ethnicity": None,
    "sexuality": None,
    "language": None,
    "religion": None,
    "religious_belief": None,
    "education_level": None,
    "employment_status": None,
    "marital_status": None,
    # Health attributes — not identifiers
    "blood_type": None,
    # Political / ideological — sensitive attributes, not identifiers
    "political_view": None,
    "political_affiliation": None,
}

# Default cache location for Nemotron-PII
_NEMOTRON_CACHE_DIR = Path.home() / ".cache" / "openlabels" / "benchmark"


def _map_entity(raw_label: str, mapping: dict[str, str | None]) -> str | None:
    """Map a dataset label to an OpenLabels entity type.

    Returns None if the label should be excluded from scoring.
    """
    key = raw_label.lower().strip().replace(" ", "_").replace("-", "_")
    result = mapping.get(key)
    if result is None and key in mapping:
        return None  # Explicitly mapped to None = excluded
    if result is not None:
        return result
    # Pass through unknown types in UPPER_CASE
    return raw_label.upper().replace(" ", "_")


def _parse_pii_spans(
    text: str,
    spans_raw: str | list,
    mapping: dict[str, str | None],
) -> list[GoldSpan]:
    """Parse a pii_spans field (JSON string or list) into GoldSpan objects."""
    if isinstance(spans_raw, str):
        try:
            spans = json.loads(spans_raw)
        except json.JSONDecodeError:
            return []
    elif isinstance(spans_raw, list):
        spans = spans_raw
    else:
        return []

    gold: list[GoldSpan] = []
    for span in spans:
        # Handle different key naming conventions across datasets
        raw_label = (
            span.get("label")
            or span.get("type")
            or span.get("entity_type")
            or span.get("pii_type")
            or span.get("entity")
            or span.get("tag")
            or span.get("category")
            or ""
        )
        start = span.get("start")
        end = span.get("end")
        value = span.get("value") or span.get("text") or ""

        if start is None or end is None or not raw_label:
            continue
        start, end = int(start), int(end)

        mapped = _map_entity(raw_label, mapping)
        if mapped is None:
            continue

        if start < 0 or end <= start or end > len(text):
            continue

        actual_text = text[start:end]
        if value and value != actual_text:
            value = actual_text

        gold.append(GoldSpan(
            start=start,
            end=end,
            text=value or actual_text,
            entity_type=mapped,
            original_label=raw_label,
        ))

    return gold


def _resolve_entity_positions(
    text: str,
    entities: list[dict],
    mapping: dict[str, str | None],
) -> list[GoldSpan]:
    """Resolve entities without offsets by finding them in the text.

    Handles the Gretel PII format: [{entity: "value", types: ["label"]}].
    Finds each entity value in the text and creates GoldSpan with offsets.

    When the same entity value appears multiple times in the entity list,
    each occurrence is matched to a separate position in the text (if
    available), so duplicate mentions are correctly grounded.
    """
    gold: list[GoldSpan] = []
    used_ranges: list[tuple[int, int]] = []

    # Count how many times each (value, label) pair appears so we can
    # resolve duplicates to distinct text positions.
    for ent in entities:
        value = ent.get("entity") or ent.get("value") or ""
        types = ent.get("types") or []
        if not value or not types:
            continue

        raw_label = types[0] if isinstance(types, list) else str(types)
        mapped = _map_entity(raw_label, mapping)
        if mapped is None:
            continue

        # Find the next non-overlapping occurrence in text
        search_start = 0
        found = False
        while True:
            idx = text.find(value, search_start)
            if idx == -1:
                break
            end = idx + len(value)
            # Check if this range overlaps with already-used ranges
            overlaps = any(
                not (end <= us or idx >= ue) for us, ue in used_ranges
            )
            if not overlaps:
                used_ranges.append((idx, end))
                gold.append(GoldSpan(
                    start=idx,
                    end=end,
                    text=value,
                    entity_type=mapped,
                    original_label=raw_label,
                ))
                found = True
                break
            search_start = idx + 1

        # If no non-overlapping position found, try to find ANY position
        # (the value may be a substring of an already-matched longer span)
        if not found:
            idx = text.find(value)
            if idx != -1:
                end = idx + len(value)
                used_ranges.append((idx, end))
                gold.append(GoldSpan(
                    start=idx,
                    end=end,
                    text=value,
                    entity_type=mapped,
                    original_label=raw_label,
                ))

    return gold


def load_gretel_pii(
    path: str | Path,
    *,
    sample_size: int | None = None,
    seed: int = 42,
    min_entities: int = 1,
    max_text_length: int = 10_000,
) -> list[BenchmarkSample]:
    """Load Gretel PII-Masking EN v1 dataset from JSONL.

    Handles format: {text, entities: [{entity, types}]} where entities
    have values but no start/end offsets (resolved by text search).
    """
    path = Path(path)
    # Auto-resolve .jsonl -> .jsonl.gz
    if not path.exists() and path.suffix != ".gz":
        gz_path = path.with_suffix(path.suffix + ".gz")
        if gz_path.exists():
            path = gz_path
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    samples: list[BenchmarkSample] = []
    skipped = 0

    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            text = record.get("text") or record.get("generated_text") or ""
            if not text or len(text) > max_text_length:
                skipped += 1
                continue

            entities_raw = record.get("entities") or []
            if isinstance(entities_raw, str):
                try:
                    entities_raw = json.loads(entities_raw)
                except json.JSONDecodeError:
                    entities_raw = []

            gold_spans = _resolve_entity_positions(
                text, entities_raw, GRETEL_PII_TO_OPENLABELS
            )

            if len(gold_spans) < min_entities:
                skipped += 1
                continue

            samples.append(BenchmarkSample(
                sample_id=idx,
                text=text,
                gold_spans=gold_spans,
                language="en",
            ))

    logger.info(
        "gretel_pii: loaded %d samples from %s (skipped %d)",
        len(samples), path, skipped,
    )

    if sample_size is not None and sample_size < len(samples):
        rng = random.Random(seed)
        samples = rng.sample(samples, sample_size)

    return samples


def load_gretel_finance(
    path: str | Path,
    *,
    sample_size: int | None = None,
    seed: int = 42,
    min_entities: int = 1,
    max_text_length: int = 10_000,
    language: str | None = "English",
) -> list[BenchmarkSample]:
    """Load Gretel Synthetic PII Finance Multilingual dataset from JSONL.

    Expected columns: generated_text, pii_spans, language
    Filters to specified language (default: English).
    """
    return _load_jsonl(
        path=path,
        text_field="generated_text",
        spans_field="pii_spans",
        mapping=GRETEL_FINANCE_TO_OPENLABELS,
        sample_size=sample_size,
        seed=seed,
        min_entities=min_entities,
        max_text_length=max_text_length,
        language_field="language" if language else None,
        language_value=language,
        dataset_name="gretel_finance",
    )


def load_generic_jsonl(
    path: str | Path,
    *,
    text_field: str = "text",
    spans_field: str = "entities",
    mapping: dict[str, str | None] | None = None,
    sample_size: int | None = None,
    seed: int = 42,
    min_entities: int = 1,
    max_text_length: int = 10_000,
) -> list[BenchmarkSample]:
    """Load any JSONL dataset with text + entity span annotations.

    This is the universal adapter for PII datasets.  Span annotations
    should be JSON arrays of objects with at least {start, end, label}.
    """
    return _load_jsonl(
        path=path,
        text_field=text_field,
        spans_field=spans_field,
        mapping=mapping or GRETEL_PII_TO_OPENLABELS,
        sample_size=sample_size,
        seed=seed,
        min_entities=min_entities,
        max_text_length=max_text_length,
        dataset_name="generic",
    )


def _load_jsonl(
    path: str | Path,
    *,
    text_field: str,
    spans_field: str,
    mapping: dict[str, str | None],
    sample_size: int | None,
    seed: int,
    min_entities: int,
    max_text_length: int,
    language_field: str | None = None,
    language_value: str | None = None,
    dataset_name: str = "unknown",
) -> list[BenchmarkSample]:
    """Core JSONL loader with filtering and sampling."""
    path = Path(path)
    # Auto-resolve: if caller passes .jsonl but only .jsonl.gz exists, use that
    if not path.exists() and not path.suffix == ".gz":
        gz_path = path.with_suffix(path.suffix + ".gz")
        if gz_path.exists():
            path = gz_path
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    samples: list[BenchmarkSample] = []
    skipped_lang = 0
    skipped_text_len = 0
    skipped_min_ents = 0
    skipped_parse = 0

    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped_parse += 1
                continue

            # Language filter
            if language_field and language_value:
                lang = record.get(language_field, "")
                if lang != language_value:
                    skipped_lang += 1
                    continue

            # Get text — try primary field, then fallbacks
            text = record.get(text_field) or record.get("text") or record.get("content") or ""
            if not text:
                skipped_parse += 1
                continue

            if len(text) > max_text_length:
                skipped_text_len += 1
                continue

            # Get spans
            spans_raw = record.get(spans_field) or record.get("entities") or record.get("pii_spans") or "[]"
            gold_spans = _parse_pii_spans(text, spans_raw, mapping)

            if len(gold_spans) < min_entities:
                skipped_min_ents += 1
                continue

            # Detect language from record if available
            lang = "en"
            if language_field:
                raw_lang = record.get(language_field, "en")
                if isinstance(raw_lang, str):
                    lang = _LANGUAGE_NAME_TO_CODE.get(
                        raw_lang.strip().lower(), raw_lang[:2].lower()
                    )

            samples.append(BenchmarkSample(
                sample_id=idx,
                text=text,
                gold_spans=gold_spans,
                language=lang,
            ))

    logger.info(
        "%s: loaded %d samples from %s (skipped: %d lang, %d too-long, "
        "%d below min_entities, %d parse errors)",
        dataset_name, len(samples), path,
        skipped_lang, skipped_text_len, skipped_min_ents, skipped_parse,
    )

    if sample_size is not None and sample_size < len(samples):
        rng = random.Random(seed)
        samples = rng.sample(samples, sample_size)

    return samples


def list_entity_types(samples: list[BenchmarkSample]) -> dict[str, int]:
    """Count entity types across a set of samples (useful for dataset inspection)."""
    counts: dict[str, int] = {}
    for s in samples:
        for g in s.gold_spans:
            counts[g.entity_type] = counts.get(g.entity_type, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def dataset_summary(samples: list[BenchmarkSample]) -> str:
    """Return a formatted summary of a loaded dataset."""
    type_counts = list_entity_types(samples)
    total_entities = sum(type_counts.values())
    lines = [
        f"Samples: {len(samples)}",
        f"Total entities: {total_entities}",
        f"Entity types: {len(type_counts)}",
        "",
        f"{'Entity Type':25s}  {'Count':>6s}  {'%':>6s}",
        "-" * 42,
    ]
    for etype, count in type_counts.items():
        pct = 100.0 * count / total_entities if total_entities else 0
        lines.append(f"{etype:25s}  {count:6d}  {pct:5.1f}%")
    return "\n".join(lines)


# ── NVIDIA Nemotron-PII dataset ────────────────────────────────────────


def _parse_tagged_text(text_tagged: str, mapping: dict[str, str | None]) -> tuple[str, list[GoldSpan]]:
    """Extract PII spans from XML-tagged text like ``<label>value</label>``.

    Returns the plain text (tags stripped) and the gold spans with character
    offsets computed against the plain text.
    """
    import re

    # Match <label>value</label> patterns (non-greedy value)
    tag_pattern = re.compile(r"<([a-zA-Z_][a-zA-Z0-9_]*)>(.*?)</\1>", re.DOTALL)

    plain_parts: list[str] = []
    gold: list[GoldSpan] = []
    last_end = 0

    for m in tag_pattern.finditer(text_tagged):
        tag_start = m.start()
        raw_label = m.group(1)
        value = m.group(2)

        # Append text before this tag
        plain_parts.append(text_tagged[last_end:tag_start])
        span_start = sum(len(p) for p in plain_parts)

        # Append the entity value (without tags)
        plain_parts.append(value)
        span_end = span_start + len(value)

        mapped = _map_entity(raw_label, mapping)
        if mapped is not None and value.strip():
            gold.append(GoldSpan(
                start=span_start,
                end=span_end,
                text=value,
                entity_type=mapped,
                original_label=raw_label,
            ))

        last_end = m.end()

    # Append remaining text
    plain_parts.append(text_tagged[last_end:])
    plain_text = "".join(plain_parts)

    return plain_text, gold


def _coerce_spans_to_list(spans_raw: object) -> list[dict]:
    """Coerce a HuggingFace spans column value to a list of dicts.

    Handles:
    - dict-of-lists (Arrow columnar Sequence format)
    - list-of-dicts (already correct)
    - JSON string
    - Python repr string (single quotes)
    """
    if isinstance(spans_raw, dict):
        return _dict_of_lists_to_list_of_dicts(spans_raw)
    if isinstance(spans_raw, list):
        return spans_raw
    if isinstance(spans_raw, str):
        try:
            parsed = json.loads(spans_raw)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass
    return []


def _download_nemotron_cache(
    cache_dir: Path,
    cache_path: Path,
) -> list[BenchmarkSample]:
    """Download NVIDIA Nemotron-PII from HuggingFace and write JSONL cache.

    Uses the ``test`` split (50 k records) for evaluation benchmarking.
    The ``spans`` column contains character-level annotations::

        [{"start": 52, "end": 61, "text": "johndoe88", "label": "user_name"}, ...]

    HuggingFace ``datasets`` (v4+) returns ``Sequence(Feature)`` columns as
    dict-of-lists (Arrow columnar format).  This function converts them to
    list-of-dicts before parsing.

    If the ``spans`` column yields 0 annotations, falls back to parsing
    ``text_tagged`` (XML-tagged text with ``<label>value</label>`` markup).
    """
    try:
        from datasets import load_dataset as hf_load
    except ImportError as exc:
        raise ImportError(
            "The 'datasets' package is required for downloading Nemotron-PII. "
            "Install it with: pip install 'openlabels[benchmark]'"
        ) from exc

    cache_dir.mkdir(parents=True, exist_ok=True)

    ds = hf_load("nvidia/Nemotron-PII", split="test")

    # ── Diagnostic: log schema and first-row spans ──────────────────
    try:
        logger.info("Nemotron-PII schema: %s", ds.features)
    except Exception:
        pass

    _log_first_rows_diagnostic(ds, n=3)

    # ── Primary pass: parse spans column ────────────────────────────
    samples, stats = _nemotron_pass_spans(ds)

    # ── Fallback: parse text_tagged if spans were all empty ─────────
    has_text_tagged = "text_tagged" in (ds.column_names if hasattr(ds, "column_names") else [])
    if stats["total_annotations"] == 0 and has_text_tagged:
        logger.warning(
            "Nemotron-PII: spans column yielded 0 annotations; "
            "falling back to text_tagged column"
        )
        samples, stats = _nemotron_pass_tagged(ds)

    density = stats["total_gold_kept"] / len(samples) if samples else 0
    logger.info(
        "Nemotron-PII download: %d samples, %d total annotations, "
        "%d gold spans kept (%.1f per sample), "
        "%d skipped (no text: %d, bad format: %d)",
        len(samples), stats["total_annotations"], stats["total_gold_kept"],
        density,
        stats["skipped_no_text"] + stats["skipped_format"],
        stats["skipped_no_text"], stats["skipped_format"],
    )

    if not samples:
        logger.warning("Nemotron-PII download returned 0 samples; skipping cache write")
        return samples

    _write_nemotron_cache(cache_path, samples)
    logger.info("Cached %d Nemotron-PII samples to %s", len(samples), cache_path)
    return samples


def _log_first_rows_diagnostic(ds: object, n: int = 3) -> None:
    """Log the raw spans format of the first *n* rows for debugging."""
    try:
        for i in range(min(n, len(ds))):
            row = ds[i]
            spans_raw = row.get("spans")
            text_tagged = row.get("text_tagged", "")
            logger.info(
                "Nemotron-PII row %d diagnostic: "
                "type(spans)=%s, "
                "keys=%s, "
                "repr(spans)=%.300s, "
                "text[:120]=%s, "
                "text_tagged[:120]=%s",
                i,
                type(spans_raw).__name__,
                list(spans_raw.keys()) if isinstance(spans_raw, dict) else "N/A",
                repr(spans_raw),
                repr(row.get("text", "")[:120]),
                repr(text_tagged[:120]) if text_tagged else "N/A",
            )
    except Exception as exc:
        logger.warning("Nemotron-PII diagnostic failed: %s", exc)


def _nemotron_pass_spans(ds: object) -> tuple[list[BenchmarkSample], dict]:
    """First pass: parse the ``spans`` column."""
    samples: list[BenchmarkSample] = []
    stats = {
        "total_annotations": 0,
        "total_gold_kept": 0,
        "skipped_no_text": 0,
        "skipped_format": 0,
        "reject_no_label": 0,
        "reject_no_offsets": 0,
        "reject_unmapped": 0,
        "reject_oob": 0,
    }
    idx = 0

    for row in ds:
        text = row.get("text", "")
        if not text:
            stats["skipped_no_text"] += 1
            continue

        spans_raw = row.get("spans")
        if spans_raw is None:
            stats["skipped_format"] += 1
            continue

        span_list = _coerce_spans_to_list(spans_raw)
        stats["total_annotations"] += len(span_list)

        gold_spans = _parse_pii_spans(text, span_list, NEMOTRON_TO_OPENLABELS)
        stats["total_gold_kept"] += len(gold_spans)

        # Detailed rejection tracking (first 5 rows only, to avoid perf hit)
        if idx < 5 and len(span_list) > 0 and len(gold_spans) == 0:
            _log_span_rejections(text, span_list, idx)

        samples.append(BenchmarkSample(
            sample_id=idx,
            text=text,
            gold_spans=gold_spans,
            language="en",
        ))
        idx += 1

    return samples, stats


def _log_span_rejections(text: str, span_list: list[dict], row_idx: int) -> None:
    """Log why each span in a row was rejected (for debugging)."""
    for i, span in enumerate(span_list[:3]):
        raw_label = (
            span.get("label") or span.get("type") or span.get("entity_type")
            or span.get("pii_type") or span.get("entity") or span.get("tag")
            or span.get("category") or ""
        )
        start = span.get("start")
        end = span.get("end")
        reason = "unknown"
        if start is None or end is None:
            reason = f"missing offsets (start={start}, end={end})"
        elif not raw_label:
            reason = f"no label found; span keys={list(span.keys())}"
        else:
            s, e = int(start), int(end)
            mapped = _map_entity(raw_label, NEMOTRON_TO_OPENLABELS)
            if mapped is None:
                reason = f"label '{raw_label}' excluded by mapping"
            elif s < 0 or e <= s or e > len(text):
                reason = (
                    f"out of bounds: start={s}, end={e}, "
                    f"text_len={len(text)}"
                )
            else:
                reason = "passed (should not be rejected)"
        logger.warning(
            "Nemotron-PII row %d span %d rejected: %s | span=%s",
            row_idx, i, reason, repr(span)[:200],
        )


def _nemotron_pass_tagged(ds: object) -> tuple[list[BenchmarkSample], dict]:
    """Fallback pass: extract spans from ``text_tagged`` XML markup."""
    samples: list[BenchmarkSample] = []
    stats = {
        "total_annotations": 0,
        "total_gold_kept": 0,
        "skipped_no_text": 0,
        "skipped_format": 0,
    }
    idx = 0

    for row in ds:
        text_tagged = row.get("text_tagged", "")
        if not text_tagged:
            stats["skipped_no_text"] += 1
            continue

        plain_text, gold_spans = _parse_tagged_text(
            text_tagged, NEMOTRON_TO_OPENLABELS
        )
        if not plain_text:
            stats["skipped_no_text"] += 1
            continue

        stats["total_annotations"] += len(gold_spans)
        stats["total_gold_kept"] += len(gold_spans)

        samples.append(BenchmarkSample(
            sample_id=idx,
            text=plain_text,
            gold_spans=gold_spans,
            language="en",
        ))
        idx += 1

    return samples, stats


def _write_nemotron_cache(cache_path: Path, samples: list[BenchmarkSample]) -> None:
    """Write parsed Nemotron-PII samples to JSONL cache."""
    with open(cache_path, "w", encoding="utf-8") as f:
        for s in samples:
            record = {
                "id": s.sample_id,
                "text": s.text,
                "language": s.language,
                "spans": [
                    {
                        "start": g.start,
                        "end": g.end,
                        "text": g.text,
                        "entity_type": g.entity_type,
                        "original_label": g.original_label,
                    }
                    for g in s.gold_spans
                ],
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _dict_of_lists_to_list_of_dicts(d: dict) -> list[dict]:
    """Convert Arrow columnar dict-of-lists to list-of-dicts."""
    if not d:
        return []
    length = None
    for v in d.values():
        if isinstance(v, (list, tuple)):
            length = len(v)
            break
    if length is None:
        return []
    result = []
    for i in range(length):
        entry = {}
        for key, vals in d.items():
            if isinstance(vals, (list, tuple)) and i < len(vals):
                entry[key] = vals[i]
            else:
                entry[key] = vals
        result.append(entry)
    return result


def _load_nemotron_cache(cache_path: Path) -> list[BenchmarkSample]:
    """Read Nemotron-PII JSONL cache, re-applying entity mapping."""
    samples: list[BenchmarkSample] = []
    with open(cache_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            gold_spans: list[GoldSpan] = []
            for s in record["spans"]:
                original = s.get("original_label", "")
                mapped = _map_entity(original, NEMOTRON_TO_OPENLABELS) if original else s["entity_type"]
                if mapped is None:
                    continue
                gold_spans.append(GoldSpan(
                    start=s["start"],
                    end=s["end"],
                    text=s["text"],
                    entity_type=mapped,
                    original_label=original,
                ))
            samples.append(BenchmarkSample(
                sample_id=record["id"],
                text=record["text"],
                gold_spans=gold_spans,
                language=record.get("language", "en"),
            ))
    return samples


def load_nemotron_pii(
    *,
    sample_size: int | None = None,
    seed: int = 42,
    cache_dir: Path | None = None,
    min_entities: int = 1,
    max_text_length: int = 10_000,
    refresh_cache: bool = False,
) -> tuple[list[BenchmarkSample], str]:
    """Load samples from the NVIDIA Nemotron-PII dataset.

    Resolution order:
    1. JSONL cache (``~/.cache/openlabels/benchmark/nemotron_pii.jsonl``)
    2. Download from HuggingFace Hub (requires ``datasets`` package)

    The Nemotron-PII dataset contains 100 k synthetic English records across
    50+ industries with span-level annotations for 55+ PII/PHI categories.
    We use the ``test`` split (50 k) for benchmarking.

    License: CC BY 4.0 (https://huggingface.co/datasets/nvidia/Nemotron-PII)
    """
    cache_dir = cache_dir or _NEMOTRON_CACHE_DIR
    cache_path = cache_dir / "nemotron_pii.jsonl"

    if refresh_cache and cache_path.exists():
        logger.info("Deleting stale Nemotron-PII cache: %s", cache_path)
        cache_path.unlink()

    samples: list[BenchmarkSample] = []
    source = "none"

    # 1. Try cache
    if cache_path.exists():
        logger.info("Loading cached Nemotron-PII from %s", cache_path)
        samples = _load_nemotron_cache(cache_path)
        if samples:
            source = f"cache ({cache_path})"
        else:
            logger.warning("Nemotron-PII cache returned 0 samples; removing")
            cache_path.unlink(missing_ok=True)

    # 2. Download from HuggingFace
    if not samples:
        try:
            logger.info("Downloading Nemotron-PII from HuggingFace...")
            samples = _download_nemotron_cache(cache_dir, cache_path)
            if samples:
                source = f"huggingface (cached to {cache_path})"
        except ImportError:
            logger.warning(
                "The 'datasets' package is not installed — cannot download "
                "Nemotron-PII from HuggingFace. Install with: "
                "pip install 'openlabels[benchmark]'"
            )
        except (ConnectionError, OSError) as exc:
            logger.warning(
                "Cannot reach HuggingFace Hub (%s) — cannot download "
                "Nemotron-PII dataset.",
                type(exc).__name__,
            )
        except Exception as exc:  # noqa: BLE001
            # httpx.ProxyError and other transport errors don't inherit
            # from ConnectionError/OSError.
            logger.warning(
                "HuggingFace download failed (%s: %s) — cannot download "
                "Nemotron-PII dataset.",
                type(exc).__name__,
                exc,
            )

    if not samples:
        from .dataset import DatasetLoadError
        raise DatasetLoadError(
            f"Failed to load Nemotron-PII dataset from any source.\n"
            f"  Cache path: {cache_path} (exists={cache_path.exists()})\n"
            "Ensure the 'datasets' package is installed:\n"
            "  pip install 'openlabels[benchmark]'"
        )

    # Filter
    filtered: list[BenchmarkSample] = []
    for s in samples:
        if len(s.text) > max_text_length:
            continue
        if len(s.gold_spans) < min_entities:
            continue
        filtered.append(s)

    logger.info(
        "Nemotron-PII: %d total, %d after filtering (min_entities=%d)",
        len(samples), len(filtered), min_entities,
    )

    if sample_size is not None and sample_size < len(filtered):
        rng = random.Random(seed)
        filtered = rng.sample(filtered, sample_size)
    elif sample_size is not None and sample_size > len(filtered):
        logger.warning(
            "Requested %d samples but only %d available. Returning all %d.",
            sample_size, len(filtered), len(filtered),
        )

    return filtered, source
