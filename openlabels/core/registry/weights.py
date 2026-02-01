"""Entity weights for risk scoring.

This module loads entity weights from weights.yaml as the primary source.
Weights define the risk/sensitivity level (1-10 scale) for each entity type.

Weight Scale:
- 10: Critical - Direct identifiers that can uniquely identify someone
      (SSN, Passport, Credit Card)
- 8-9: High - Strong identifiers or highly sensitive information
      (MRN, Driver's License, API Keys)
- 6-7: Elevated - Moderately sensitive information
      (Phone, Email, Health Plan ID)
- 4-5: Moderate - Information that contributes to identification
      (Name, Address, IP Address)
- 2-3: Low - Quasi-identifiers or context information
      (Date, City, State, Time)
- 1: Minimal - Very low risk information

Note: Weights are used by the scorer to calculate overall file risk.

Override Mechanism:
    Organizations can customize weights by creating a YAML file at one of:
    - /etc/openlabels/weights.yaml (system-wide)
    - ~/.openlabels/weights.yaml (user-specific)
    - OPENLABELS_WEIGHTS_FILE environment variable (explicit path)

    Override file format:
        SSN: 10
        EMAIL: 3
        # Only include types you want to override

    On rescan, labels are recalculated with the effective weights
    (standard + overrides) for the current environment.
"""

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Path to the bundled weights.yaml
_BUNDLED_WEIGHTS_FILE = Path(__file__).parent / "weights.yaml"

# Default weight for unknown entity types
DEFAULT_WEIGHT = 5


def _load_yaml_file(path: Path) -> Optional[Dict]:
    """
    Load a YAML file safely.

    Args:
        path: Path to the YAML file

    Returns:
        Parsed YAML content as dict, or None if loading fails
    """
    try:
        import yaml
    except ImportError:
        logger.debug("PyYAML not installed, cannot load YAML files")
        return None

    try:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.debug(f"Weights file not found: {path}")
        return None
    except Exception as e:
        logger.warning(f"Failed to load weights from {path}: {e}")
        return None


def _flatten_weights(data: Dict) -> Dict[str, int]:
    """
    Flatten categorized weights from YAML into a single dictionary.

    The YAML file has categories like 'direct_identifiers', 'healthcare', etc.
    This function extracts all entity types into a flat {ENTITY_TYPE: weight} dict.

    Args:
        data: Parsed YAML data with categories

    Returns:
        Flat dictionary mapping entity types (uppercase) to weights
    """
    flat_weights: Dict[str, int] = {}

    # Keys to skip (not categories)
    skip_keys = {'schema_version', 'default_weight'}

    for key, value in data.items():
        if key in skip_keys:
            continue
        if isinstance(value, dict):
            # This is a category with entity types
            for entity_type, weight in value.items():
                if isinstance(weight, int) and 1 <= weight <= 10:
                    flat_weights[entity_type.upper()] = weight
                else:
                    logger.warning(f"Invalid weight for {entity_type}: {weight} (must be int 1-10)")
        elif isinstance(value, int):
            # Direct entity type at root level (not recommended but supported)
            flat_weights[key.upper()] = value

    return flat_weights


@lru_cache(maxsize=1)
def _load_bundled_weights() -> Dict[str, int]:
    """
    Load weights from the bundled weights.yaml file.

    This is the primary source of entity weights. Falls back to minimal
    builtin weights if YAML loading fails.

    Returns:
        Dictionary mapping entity types to weights
    """
    data = _load_yaml_file(_BUNDLED_WEIGHTS_FILE)

    if data is not None:
        weights = _flatten_weights(data)
        logger.info(f"Loaded {len(weights)} entity weights from {_BUNDLED_WEIGHTS_FILE.name}")
        return weights

    # Fallback to minimal builtin weights
    logger.warning("Using minimal builtin weights (YAML loading failed)")
    return _BUILTIN_WEIGHTS.copy()


def _find_override_file() -> Optional[Path]:
    """
    Find the weight override file, checking in order:
    1. OPENLABELS_WEIGHTS_FILE environment variable
    2. ~/.openlabels/weights.yaml (user-specific)
    3. /etc/openlabels/weights.yaml (system-wide)

    Returns:
        Path to override file if found, None otherwise
    """
    # Check environment variable first
    env_path = os.environ.get("OPENLABELS_WEIGHTS_FILE")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path

    # Check user-specific config
    user_path = Path.home() / ".openlabels" / "weights.yaml"
    if user_path.exists():
        return user_path

    # Check system-wide config
    system_path = Path("/etc/openlabels/weights.yaml")
    if system_path.exists():
        return system_path

    return None


@lru_cache(maxsize=1)
def _load_overrides() -> Dict[str, int]:
    """
    Load weight overrides from user/system YAML file.

    Cached to avoid repeated file I/O. Cache is cleared on reload_overrides().

    Returns:
        Dict of entity_type -> weight overrides (empty if no override file)
    """
    override_file = _find_override_file()
    if override_file is None:
        return {}

    data = _load_yaml_file(override_file)
    if data is None:
        return {}

    # Validate overrides (flat format expected)
    valid_overrides: Dict[str, int] = {}
    for entity_type, weight in data.items():
        if entity_type in ('schema_version', 'default_weight'):
            continue
        if not isinstance(entity_type, str):
            logger.warning(f"Invalid override key (not string): {entity_type}")
            continue
        if isinstance(weight, dict):
            # Category format - flatten it
            for sub_type, sub_weight in weight.items():
                if isinstance(sub_weight, int) and 1 <= sub_weight <= 10:
                    valid_overrides[sub_type.upper()] = sub_weight
        elif isinstance(weight, int) and 1 <= weight <= 10:
            valid_overrides[entity_type.upper()] = weight
        else:
            logger.warning(f"Invalid weight for {entity_type}: {weight} (must be int 1-10)")

    if valid_overrides:
        logger.info(f"Loaded {len(valid_overrides)} weight overrides from {override_file}")

    return valid_overrides


def get_effective_weights() -> Dict[str, int]:
    """
    Get effective weights (bundled + overrides).

    Returns:
        Combined dict with overrides taking precedence over bundled weights
    """
    effective = _load_bundled_weights().copy()
    effective.update(_load_overrides())
    return effective


def get_weight(entity_type: str) -> int:
    """
    Get weight for an entity type.

    Args:
        entity_type: The entity type (case-insensitive)

    Returns:
        Weight from 1-10, or DEFAULT_WEIGHT if type unknown
    """
    weights = get_effective_weights()
    return weights.get(entity_type.upper(), DEFAULT_WEIGHT)


def reload_weights() -> None:
    """
    Reload all weights from disk.

    Call this after modifying the weights files to pick up changes
    without restarting the process.
    """
    _load_bundled_weights.cache_clear()
    _load_overrides.cache_clear()

    weights = get_effective_weights()
    logger.info(f"Reloaded weights: {len(weights)} entity types")


def reload_overrides() -> None:
    """
    Reload weight overrides from disk.

    Call this after modifying the override file to pick up changes
    without restarting the process.
    """
    _load_overrides.cache_clear()
    overrides = _load_overrides()
    if overrides:
        logger.info(f"Reloaded {len(overrides)} weight overrides")
    else:
        logger.info("No weight overrides loaded")



# --- Backward Compatibility ---


class _LazyWeights(dict):
    """
    Lazy-loading dict for backward compatibility with ENTITY_WEIGHTS.

    Loads weights on first access, supporting the existing API:
        from openlabels.core.registry.weights import ENTITY_WEIGHTS
        weight = ENTITY_WEIGHTS.get('SSN', 5)
    """
    _loaded = False

    def _ensure_loaded(self):
        if not self._loaded:
            self.update(get_effective_weights())
            self._loaded = True

    def __getitem__(self, key):
        self._ensure_loaded()
        return super().get(key.upper(), DEFAULT_WEIGHT)

    def get(self, key, default=None):
        self._ensure_loaded()
        if default is None:
            default = DEFAULT_WEIGHT
        return super().get(key.upper(), default)

    def __contains__(self, key):
        self._ensure_loaded()
        return super().__contains__(key.upper())

    def __iter__(self):
        self._ensure_loaded()
        return super().__iter__()

    def __len__(self):
        self._ensure_loaded()
        return super().__len__()

    def keys(self):
        self._ensure_loaded()
        return super().keys()

    def values(self):
        self._ensure_loaded()
        return super().values()

    def items(self):
        self._ensure_loaded()
        return super().items()


# Backward-compatible module-level constant
# This loads lazily on first access
ENTITY_WEIGHTS = _LazyWeights()



# --- Builtin Fallback Weights ---

# Minimal set of weights used when YAML loading fails (e.g., PyYAML not installed)
# This ensures the system works even without the full weights.yaml

_BUILTIN_WEIGHTS: Dict[str, int] = {
    # Critical identifiers
    "SSN": 10,
    "PASSPORT": 10,
    "CREDIT_CARD": 10,
    "PASSWORD": 10,
    "API_KEY": 10,
    "PRIVATE_KEY": 10,
    "AWS_ACCESS_KEY": 10,
    "AWS_SECRET_KEY": 10,
    "DATABASE_URL": 10,
    # High-risk identifiers
    "MRN": 8,
    "DIAGNOSIS": 8,
    "DRIVERS_LICENSE": 7,
    "NPI": 7,
    "HEALTH_PLAN_ID": 8,
    "GITHUB_TOKEN": 10,
    "SLACK_TOKEN": 10,
    "JWT": 8,
    # Moderate identifiers
    "EMAIL": 5,
    "PHONE": 4,
    "NAME": 5,
    "ADDRESS": 5,
    "IP_ADDRESS": 4,
    # Low-risk
    "DATE": 3,
    "CITY": 2,
    "STATE": 2,
    "AGE": 4,
}



# --- Backward Compatibility: Category Exports ---

# These provide the old category-level dictionaries for code that imports them.
# They are dynamically generated from the YAML on first access.

class _LazyCategoryWeights(dict):
    """Lazy-loading dict for a specific category."""

    def __init__(self, category_key: str):
        self._category_key = category_key
        self._loaded = False

    def _ensure_loaded(self):
        if not self._loaded:
            data = _load_yaml_file(_BUNDLED_WEIGHTS_FILE)
            if data and self._category_key in data:
                category_data = data[self._category_key]
                if isinstance(category_data, dict):
                    for k, v in category_data.items():
                        if isinstance(v, int):
                            self[k.upper()] = v
            self._loaded = True

    def __getitem__(self, key):
        self._ensure_loaded()
        return super().__getitem__(key)

    def get(self, key, default=None):
        self._ensure_loaded()
        return super().get(key, default)

    def __contains__(self, key):
        self._ensure_loaded()
        return super().__contains__(key)

    def __iter__(self):
        self._ensure_loaded()
        return super().__iter__()

    def __len__(self):
        self._ensure_loaded()
        return super().__len__()

    def keys(self):
        self._ensure_loaded()
        return super().keys()

    def values(self):
        self._ensure_loaded()
        return super().values()

    def items(self):
        self._ensure_loaded()
        return super().items()

    def update(self, *args, **kwargs):
        self._ensure_loaded()
        return super().update(*args, **kwargs)


# Category-level weight dictionaries (backward compatibility)
DIRECT_IDENTIFIER_WEIGHTS = _LazyCategoryWeights('direct_identifiers')
HEALTHCARE_WEIGHTS = _LazyCategoryWeights('healthcare')
PERSONAL_INFO_WEIGHTS = _LazyCategoryWeights('personal_info')
CONTACT_INFO_WEIGHTS = _LazyCategoryWeights('contact_info')
FINANCIAL_WEIGHTS = _LazyCategoryWeights('financial')
DIGITAL_IDENTIFIER_WEIGHTS = _LazyCategoryWeights('digital_identifiers')
CREDENTIAL_WEIGHTS = _LazyCategoryWeights('credentials')
GOVERNMENT_WEIGHTS = _LazyCategoryWeights('government')
EDUCATION_WEIGHTS = _LazyCategoryWeights('education')
LEGAL_WEIGHTS = _LazyCategoryWeights('legal')
VEHICLE_WEIGHTS = _LazyCategoryWeights('vehicle')
IMMIGRATION_WEIGHTS = _LazyCategoryWeights('immigration')
INSURANCE_WEIGHTS = _LazyCategoryWeights('insurance')
REAL_ESTATE_WEIGHTS = _LazyCategoryWeights('real_estate')
TELECOM_WEIGHTS = _LazyCategoryWeights('telecom')
BIOMETRIC_WEIGHTS = _LazyCategoryWeights('biometric')
MILITARY_WEIGHTS = _LazyCategoryWeights('military')
SENSITIVE_FILE_WEIGHTS = _LazyCategoryWeights('sensitive_files')
INTERNATIONAL_ID_WEIGHTS = _LazyCategoryWeights('international_ids')
