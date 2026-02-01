"""Settings API routes for ScrubIQ."""

import logging
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ..types import KNOWN_ENTITY_TYPES
from ..llm_client import AnthropicClient, OpenAIClient
from ..constants import API_RATE_WINDOW_SECONDS
from ..rate_limiter import check_rate_limit
from .dependencies import require_api_key
from .errors import bad_request, unauthorized, ErrorCode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/settings", tags=["settings"])


# SCHEMAS

class SettingsResponse(BaseModel):
    """Current configuration settings."""
    # Detection
    confidence_threshold: float = Field(0.85, ge=0.0, le=1.0)
    safe_harbor: bool = True
    coreference: bool = True
    
    # Entity filtering
    entity_types: Optional[List[str]] = None  # None = all types
    exclude_types: Optional[List[str]] = None
    
    # Allowlist
    allowlist: List[str] = []
    
    # Review queue
    review_threshold: float = Field(0.7, ge=0.0, le=1.0)
    
    # Performance
    device: str = "auto"  # auto, cuda, cpu
    
    # LLM
    llm_provider: str = "anthropic"
    llm_model: str = "claude-sonnet-4"  # Best balance of speed/quality


class SettingsUpdateRequest(BaseModel):
    """Update configuration settings."""
    confidence_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    safe_harbor: Optional[bool] = None
    coreference: Optional[bool] = None
    entity_types: Optional[List[str]] = None
    exclude_types: Optional[List[str]] = None
    allowlist: Optional[List[str]] = None
    review_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    device: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None


class EntityTypesResponse(BaseModel):
    """Available entity types for detection."""
    types: List[str]
    categories: Dict[str, List[str]]


class ProvidersResponse(BaseModel):
    """Available LLM providers and their models."""
    providers: Dict[str, Dict[str, Any]]


# Allowlist limits to prevent DoS
MAX_ALLOWLIST_ENTRIES = 1000  # Max total entries
MAX_ALLOWLIST_VALUE_LENGTH = 200  # Max characters per entry
MAX_ALLOWLIST_BATCH_SIZE = 100  # Max entries per request


class AllowlistUpdateRequest(BaseModel):
    """Update allowlist entries."""
    action: str = Field(..., pattern="^(add|remove|set)$")
    values: List[str] = Field(
        ...,
        max_length=MAX_ALLOWLIST_BATCH_SIZE,
        description=f"Max {MAX_ALLOWLIST_BATCH_SIZE} entries per request"
    )


# --- ENTITY TYPE CATEGORIZATION ---
def _categorize_entity_types() -> Dict[str, List[str]]:
    """
    Organize entity types into meaningful categories for the UI.
    
    Categories are ordered by typical importance/sensitivity.
    """
    
    # Define category rules: (category_name, keywords_to_match)
    # Order matters - first match wins
    category_rules = [
        # Secrets & Credentials - highest priority
        ("secrets_cloud", [
            "AWS_", "AZURE_", "GOOGLE_API", "GOOGLE_OAUTH", "FIREBASE",
        ]),
        ("secrets_code", [
            "GITHUB_", "GITLAB_", "NPM_", "PYPI_", "NUGET_",
        ]),
        ("secrets_communication", [
            "SLACK_", "DISCORD_", "TWILIO_", "SENDGRID_", "MAILCHIMP_",
        ]),
        ("secrets_payment", [
            "STRIPE_", "SQUARE_", "SHOPIFY_",
        ]),
        ("secrets_infrastructure", [
            "HEROKU_", "DATADOG_", "NEWRELIC_", "DATABASE_URL",
        ]),
        ("secrets_auth", [
            "PRIVATE_KEY", "JWT", "BASIC_AUTH", "BEARER_TOKEN", 
            "PASSWORD", "API_KEY", "SECRET",
        ]),
        
        # Government & Classification
        ("government_classification", [
            "CLASSIFICATION_", "SCI_MARKING", "DISSEMINATION_",
        ]),
        ("government_contracts", [
            "CAGE_CODE", "DUNS_", "UEI", "DOD_CONTRACT", "GSA_CONTRACT",
        ]),
        ("government_security", [
            "CLEARANCE_", "ITAR_", "EAR_MARKING",
        ]),
        
        # Financial
        ("financial_payment", [
            "CREDIT_CARD", "CREDITCARD", "CC", "ACCOUNT_NUMBER", "ACCOUNT", 
            "BANK_ACCOUNT", "IBAN", "ABA_ROUTING", "ROUTING", "BIC", "SWIFT",
        ]),
        ("financial_securities", [
            "CUSIP", "ISIN", "SEDOL", "FIGI", "LEI",
        ]),
        ("cryptocurrency", [
            "BITCOIN", "ETHEREUM", "CRYPTO_", "SOLANA_", "CARDANO_",
            "LITECOIN_", "DOGECOIN_", "XRP_",
        ]),
        
        # Personal Identifiers
        ("names", [
            "NAME", "PERSON", "PER", "PATIENT", "DOCTOR", "PHYSICIAN", 
            "NURSE", "STAFF", "FIRSTNAME", "LASTNAME", "MIDDLENAME",
            "PREFIX", "SUFFIX", "FULLNAME", "HCW",
        ]),
        ("dates", [
            "DATE", "TIME", "BIRTHDAY", "DOB", "BIRTH",
        ]),
        ("locations", [
            "ADDRESS", "ZIP", "CITY", "STATE", "COUNTRY", "COUNTY",
            "GPS", "LATITUDE", "LONGITUDE", "COORDINATE", "GPE", "LOC",
            "STREET", "POSTCODE", "LOCATION", "ROOM",
        ]),
        
        # Government IDs
        ("identifiers_government", [
            "SSN", "SOCIAL_SECURITY", "UKNI", "DRIVER", "LICENSE",
            "STATE_ID", "PASSPORT", "MILITARY_ID", "EDIPI", "DOD_ID",
        ]),
        
        # Medical IDs
        ("identifiers_medical", [
            "MRN", "MEDICAL_RECORD", "NPI", "DEA", "MEDICAL_LICENSE",
            "ENCOUNTER_ID", "ACCESSION_ID", "HEALTH_PLAN", "MEMBERID",
            "MEMBER_ID", "MEDICARE_ID", "PHARMACY_ID",
        ]),
        
        # Vehicle IDs
        ("identifiers_vehicle", [
            "VIN", "VEHICLE", "LICENSE_PLATE", "PLATE_NUMBER",
        ]),
        
        # Contact
        ("contact", [
            "PHONE", "TEL", "MOBILE", "CELL", "EMAIL", "FAX", "PAGER", "URL", "USERNAME",
        ]),
        
        # Network/Device
        ("network", [
            "IP_ADDRESS", "IP", "IPV4", "IPV6", "MAC_ADDRESS", "MAC",
            "DEVICE_ID", "IMEI", "DEVICE", "BIOID", "USERAGENT", "USER_AGENT",
            "BIOMETRIC", "FINGERPRINT", "RETINAL", "IRIS", "VOICEPRINT", "DNA",
            "IMAGE_ID", "PHOTO_ID", "DICOM_UID",
        ]),
        
        # Medical
        ("medical", [
            "DRUG", "LAB_TEST", "DIAGNOSIS", "PROCEDURE", "PAYER",
            "RX_NUMBER", "PRESCRIPTION", "SCRIPT",
        ]),
        
        # Organization
        ("organization", [
            "FACILITY", "HOSPITAL", "ORG", "ORGANIZATION", "VENDOR",
            "COMPANY", "PROFESSION", "OCCUPATION", "JOB",
        ]),
    ]
    
    categories: Dict[str, List[str]] = {name: [] for name, _ in category_rules}
    categories["other"] = []  # Catch-all
    
    categorized = set()
    
    for entity_type in KNOWN_ENTITY_TYPES:
        matched = False
        for category_name, keywords in category_rules:
            if any(kw in entity_type.upper() for kw in keywords):
                categories[category_name].append(entity_type)
                categorized.add(entity_type)
                matched = True
                break
        
        if not matched:
            categories["other"].append(entity_type)
    
    # Remove empty categories and sort values
    return {k: sorted(v) for k, v in categories.items() if v}


# Rate limits for settings operations
SETTINGS_READ_RATE_LIMIT = 60  # Max reads per window
SETTINGS_WRITE_RATE_LIMIT = 20  # Max writes per window


# --- ROUTES ---
@router.get("", response_model=SettingsResponse)
async def get_settings(request: Request, cr=Depends(require_api_key)) -> SettingsResponse:
    """
    Get current configuration settings.

    Returns all configurable settings including detection thresholds,
    entity type filters, allowlist, and LLM configuration.
    """
    check_rate_limit(request, action="settings_read", limit=SETTINGS_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not cr.is_unlocked:
        raise unauthorized("Session not unlocked", error_code=ErrorCode.NOT_AUTHENTICATED)
    
    config = cr.config
    
    return SettingsResponse(
        confidence_threshold=getattr(config, 'confidence_threshold', 0.85),
        safe_harbor=getattr(config, 'safe_harbor_enabled', True),
        coreference=getattr(config, 'coref_enabled', True),
        entity_types=getattr(config, 'entity_types', None),
        exclude_types=getattr(config, 'exclude_types', None),
        allowlist=list(getattr(config, 'allowlist', [])),
        review_threshold=getattr(config, 'review_threshold', 0.7),
        device=getattr(config, 'device', 'auto'),
        llm_provider=getattr(config, 'llm_provider', 'anthropic'),
        llm_model=getattr(config, 'llm_model', 'claude-sonnet-4'),
    )


@router.put("", response_model=SettingsResponse)
async def update_settings(
    request: Request,
    body: SettingsUpdateRequest,
    cr=Depends(require_api_key),
) -> SettingsResponse:
    """
    Update configuration settings.

    Only provided fields are updated. Returns the full updated configuration.
    Some settings may require restart to take effect.
    """
    check_rate_limit(request, action="settings_write", limit=SETTINGS_WRITE_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not cr.is_unlocked:
        raise unauthorized("Session not unlocked", error_code=ErrorCode.NOT_AUTHENTICATED)
    
    config = cr.config

    # Update only provided fields
    if body.confidence_threshold is not None:
        config.confidence_threshold = body.confidence_threshold

    if body.safe_harbor is not None:
        config.safe_harbor_enabled = body.safe_harbor

    if body.coreference is not None:
        config.coref_enabled = body.coreference

    if body.entity_types is not None:
        # Validate entity types
        invalid = set(body.entity_types) - KNOWN_ENTITY_TYPES
        if invalid:
            raise bad_request(
                f"Unknown entity types: {invalid}",
                error_code=ErrorCode.VALIDATION_ERROR
            )
        config.entity_types = body.entity_types if body.entity_types else None

    if body.exclude_types is not None:
        invalid = set(body.exclude_types) - KNOWN_ENTITY_TYPES
        if invalid:
            raise bad_request(
                f"Unknown entity types: {invalid}",
                error_code=ErrorCode.VALIDATION_ERROR
            )
        config.exclude_types = body.exclude_types if body.exclude_types else None

    if body.allowlist is not None:
        config.allowlist = set(body.allowlist)

    if body.review_threshold is not None:
        config.review_threshold = body.review_threshold

    if body.device is not None:
        if body.device not in ("auto", "cuda", "cpu"):
            raise bad_request(
                f"Invalid device: {body.device}. Must be auto, cuda, or cpu",
                error_code=ErrorCode.VALIDATION_ERROR
            )
        config.device = body.device

    if body.llm_provider is not None:
        if body.llm_provider not in ("anthropic", "openai"):
            raise bad_request(
                f"Invalid provider: {body.llm_provider}. Must be anthropic or openai",
                error_code=ErrorCode.VALIDATION_ERROR
            )
        config.llm_provider = body.llm_provider

    if body.llm_model is not None:
        config.llm_model = body.llm_model

    logger.info(f"Settings updated: {body.model_dump(exclude_none=True)}")

    return await get_settings(request, cr)


@router.get("/entity-types", response_model=EntityTypesResponse)
async def get_entity_types(request: Request, _=Depends(require_api_key)) -> EntityTypesResponse:
    """
    Get available entity types for PHI/PII detection.
    
    Returns all known entity types organized by category.
    Use these values for entity_types and exclude_types settings.
    
    Categories:
    - secrets_cloud: AWS, Azure, Google Cloud credentials
    - secrets_code: GitHub, GitLab, NPM, PyPI tokens
    - secrets_communication: Slack, Discord, Twilio tokens
    - secrets_payment: Stripe, Square, Shopify keys
    - secrets_infrastructure: Heroku, Datadog, database URLs
    - secrets_auth: Private keys, JWTs, passwords
    - government_classification: Security classification markings
    - government_contracts: CAGE, DUNS, DoD/GSA contracts
    - government_security: Clearances, ITAR, EAR
    - financial_payment: Credit cards, bank accounts, IBAN
    - financial_securities: CUSIP, ISIN, SEDOL, FIGI
    - cryptocurrency: Bitcoin, Ethereum, seed phrases
    - names: Person names, patient names, provider names
    - dates: Dates, DOB, timestamps
    - locations: Addresses, coordinates, ZIP codes
    - identifiers_government: SSN, driver license, passport
    - identifiers_medical: MRN, NPI, DEA
    - identifiers_vehicle: VIN, license plates
    - contact: Phone, email, fax, URL
    - network: IP, MAC, device IDs, biometrics
    - medical: Drugs, diagnoses, procedures
    - organization: Facilities, companies, job titles
    """
    check_rate_limit(request, action="settings_read", limit=SETTINGS_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    categories = _categorize_entity_types()

    return EntityTypesResponse(
        types=sorted(KNOWN_ENTITY_TYPES),
        categories=categories,
    )


@router.get("/providers", response_model=ProvidersResponse)
async def get_providers(request: Request, _=Depends(require_api_key)) -> ProvidersResponse:
    """
    Get available LLM providers and their models.
    
    Returns provider information including available models,
    required environment variables, and current availability status.
    """
    check_rate_limit(request, action="settings_read", limit=SETTINGS_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    anthropic = AnthropicClient()
    openai = OpenAIClient()
    
    return ProvidersResponse(
        providers={
            "anthropic": {
                "name": "Anthropic",
                "models": anthropic.list_models(),
                "default_model": "claude-sonnet-4",
                "env_var": "ANTHROPIC_API_KEY",
                "available": anthropic.is_available(),
                "docs": "https://docs.anthropic.com",
            },
            "openai": {
                "name": "OpenAI",
                "models": openai.list_models(),
                "default_model": "gpt-4o",
                "env_var": "OPENAI_API_KEY",
                "available": openai.is_available(),
                "docs": "https://platform.openai.com/docs",
            },
        }
    )


@router.get("/allowlist", response_model=List[str])
async def get_allowlist(request: Request, cr=Depends(require_api_key)) -> List[str]:
    """
    Get current allowlist entries.

    Allowlisted values are not redacted even if detected as PHI.
    """
    check_rate_limit(request, action="settings_read", limit=SETTINGS_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not cr.is_unlocked:
        raise unauthorized("Session not unlocked", error_code=ErrorCode.NOT_AUTHENTICATED)

    return sorted(getattr(cr.config, 'allowlist', []))


@router.post("/allowlist")
async def update_allowlist(
    request: Request,
    body: AllowlistUpdateRequest,
    cr=Depends(require_api_key),
) -> Dict[str, Any]:
    """
    Update allowlist entries.

    Actions:
    - add: Add values to existing allowlist
    - remove: Remove values from allowlist
    - set: Replace entire allowlist with provided values

    Limits:
    - Max {MAX_ALLOWLIST_ENTRIES} total entries
    - Max {MAX_ALLOWLIST_VALUE_LENGTH} chars per entry
    - Max {MAX_ALLOWLIST_BATCH_SIZE} entries per request
    """
    check_rate_limit(request, action="settings_write", limit=SETTINGS_WRITE_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not cr.is_unlocked:
        raise unauthorized("Session not unlocked", error_code=ErrorCode.NOT_AUTHENTICATED)

    # Validate entry lengths (DoS prevention)
    for value in body.values:
        if len(value) > MAX_ALLOWLIST_VALUE_LENGTH:
            raise bad_request(
                f"Allowlist entry exceeds max length of {MAX_ALLOWLIST_VALUE_LENGTH} characters",
                error_code=ErrorCode.VALIDATION_ERROR
            )

    current = set(getattr(cr.config, 'allowlist', []))

    if body.action == "add":
        # Check total size limit before adding
        new_size = len(current | set(body.values))
        if new_size > MAX_ALLOWLIST_ENTRIES:
            raise bad_request(
                f"Allowlist would exceed max size of {MAX_ALLOWLIST_ENTRIES} entries",
                error_code=ErrorCode.VALIDATION_ERROR
            )
        current.update(body.values)
        message = f"Added {len(body.values)} entries"
    elif body.action == "remove":
        current -= set(body.values)
        message = f"Removed {len(body.values)} entries"
    elif body.action == "set":
        if len(body.values) > MAX_ALLOWLIST_ENTRIES:
            raise bad_request(
                f"Allowlist exceeds max size of {MAX_ALLOWLIST_ENTRIES} entries",
                error_code=ErrorCode.VALIDATION_ERROR
            )
        current = set(body.values)
        message = f"Set {len(body.values)} entries"

    cr.config.allowlist = current

    logger.info(f"Allowlist updated: {body.action} {len(body.values)} values")

    return {
        "success": True,
        "message": message,
        "count": len(current),
        "allowlist": sorted(current),
    }


@router.get("/thresholds")
async def get_thresholds(request: Request, cr=Depends(require_api_key)) -> Dict[str, Any]:
    """
    Get detection thresholds by entity type.

    Returns global threshold and any per-type overrides.
    """
    check_rate_limit(request, action="settings_read", limit=SETTINGS_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not cr.is_unlocked:
        raise unauthorized("Session not unlocked", error_code=ErrorCode.NOT_AUTHENTICATED)

    config = cr.config

    return {
        "global": getattr(config, 'confidence_threshold', 0.85),
        "review": getattr(config, 'review_threshold', 0.7),
        "per_type": getattr(config, 'type_thresholds', {}),
    }


@router.put("/thresholds")
async def update_thresholds(
    request: Request,
    body: Dict[str, Any],
    cr=Depends(require_api_key),
) -> Dict[str, Any]:
    """
    Update detection thresholds.

    Body:
    - global: Global confidence threshold (0.0-1.0)
    - review: Review queue threshold (0.0-1.0)
    - per_type: Dict of entity_type -> threshold overrides
    """
    check_rate_limit(request, action="settings_write", limit=SETTINGS_WRITE_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not cr.is_unlocked:
        raise unauthorized("Session not unlocked", error_code=ErrorCode.NOT_AUTHENTICATED)

    config = cr.config

    if "global" in body:
        val = body["global"]
        if not 0 <= val <= 1:
            raise bad_request("Global threshold must be 0.0-1.0", error_code=ErrorCode.VALIDATION_ERROR)
        config.confidence_threshold = val

    if "review" in body:
        val = body["review"]
        if not 0 <= val <= 1:
            raise bad_request("Review threshold must be 0.0-1.0", error_code=ErrorCode.VALIDATION_ERROR)
        config.review_threshold = val

    if "per_type" in body:
        for entity_type, threshold in body["per_type"].items():
            if entity_type not in KNOWN_ENTITY_TYPES:
                raise bad_request(f"Unknown entity type: {entity_type}", error_code=ErrorCode.VALIDATION_ERROR)
            if not 0 <= threshold <= 1:
                raise bad_request(f"Threshold for {entity_type} must be 0.0-1.0", error_code=ErrorCode.VALIDATION_ERROR)

        if not hasattr(config, 'type_thresholds'):
            config.type_thresholds = {}
        config.type_thresholds.update(body["per_type"])

    logger.info(f"Thresholds updated: {body}")

    return await get_thresholds(request, cr)
