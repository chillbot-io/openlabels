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

import ast
import gzip
import json
import logging
import random
from pathlib import Path

from .dataset import BenchmarkSample, GoldSpan

logger = logging.getLogger(__name__)


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
        # Handle different key naming conventions
        raw_label = (
            span.get("label")
            or span.get("type")
            or span.get("entity_type")
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
    """
    gold: list[GoldSpan] = []
    used_ranges: list[tuple[int, int]] = []

    for ent in entities:
        value = ent.get("entity") or ent.get("value") or ""
        types = ent.get("types") or []
        if not value or not types:
            continue

        raw_label = types[0] if isinstance(types, list) else str(types)
        mapped = _map_entity(raw_label, mapping)
        if mapped is None:
            continue

        # Find the entity in text, avoiding already-used ranges
        search_start = 0
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
                break
            search_start = idx + 1

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
                    try:
                        entities_raw = ast.literal_eval(entities_raw)
                    except (ValueError, SyntaxError):
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
                    lang = raw_lang[:2].lower()

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
