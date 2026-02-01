"""Token store with SQLite persistence.

IMPORTANT: This module does NOT perform fuzzy matching.
Entity identity decisions are made by EntityRegistry.
TokenStore only stores token ↔ value mappings.

If you need to match partial names or handle entity variants,
use EntityRegistry.register() which will return an entity_id,
then call TokenStore.get_or_create_by_entity(entity_id, ...).

TOKEN NAMESPACE BEHAVIOR
========================

Tokens are scoped by (session_id, conversation_id) pairs:

1. SESSION-WIDE TOKENS (conversation_id="")
   - Used when no conversation_id is provided
   - Tokens are shared across all conversations in the session
   - Use case: Single-document redaction, batch processing
   - Example: A patient's name "John Smith" → [PATIENT_1] everywhere

2. CONVERSATION-SCOPED TOKENS (conversation_id="conv_123")
   - Tokens are isolated per conversation
   - Same PHI gets different tokens in different conversations
   - Use case: Multi-tenant chat, privacy between conversations
   - Example: "John Smith" → [PATIENT_1] in conv_1, [PATIENT_1] in conv_2
     (both are _1 because counters are per-conversation)

3. CROSS-CONVERSATION ENTITY PERSISTENCE
   - For entity memory across conversations (e.g., "remember patient names"),
     use the EntityRegistry + get_or_create_by_entity() API
   - The entity_id (from EntityRegistry) acts as a global key
   - Same entity_id always maps to the same token within a session
   - This allows "known entities" detection across conversation boundaries

IMPORTANT CONSIDERATIONS:

- Token counters are per (session_id, conversation_id, prefix)
- [PATIENT_1] in conv_A is DIFFERENT from [PATIENT_1] in conv_B
- To restore text, you MUST use the same conversation_id that created the token
- Session-wide mode (conversation_id="") is recommended for:
  * Document redaction pipelines
  * Single-user applications
  * When you want consistent tokens across messages
- Conversation-scoped mode is recommended for:
  * Multi-user chat applications
  * When conversations must be privacy-isolated
  * Compliance scenarios requiring conversation-level audit trails

MIGRATION NOTE:
- Legacy code that doesn't pass conversation_id uses session-wide tokens
- New code should explicitly choose the appropriate scoping
"""

import hashlib
import logging
import threading
from datetime import datetime
from typing import Optional, List, Dict, Set

from .database import Database
from ..crypto import KeyManager
from ..crypto.aes import CryptoError
from ..types import TokenEntry
from ..constants import MAX_TOKEN_COUNT


logger = logging.getLogger(__name__)


# Token type to display prefix mapping
# Comprehensive mapping for all KNOWN_ENTITY_TYPES
# See types.py:KNOWN_ENTITY_TYPES for the full list
TOKEN_PREFIX = {
    # --- NAMES ---
    "NAME": "NAME",
    "NAME_PATIENT": "PATIENT",
    "NAME_PROVIDER": "PROVIDER",
    "NAME_RELATIVE": "RELATIVE",
    "PERSON": "NAME",
    "PER": "NAME",
    "PATIENT": "PATIENT",
    "DOCTOR": "PROVIDER",
    "PHYSICIAN": "PROVIDER",
    "NURSE": "PROVIDER",
    "STAFF": "PROVIDER",
    "HCW": "PROVIDER",  # Healthcare Worker (Stanford PHI-BERT)
    "FIRSTNAME": "NAME",
    "LASTNAME": "NAME",
    "MIDDLENAME": "NAME",
    "PREFIX": "NAME",
    "SUFFIX": "NAME",
    "FULLNAME": "NAME",
    "RELATIVE": "RELATIVE",
    "FAMILY": "RELATIVE",

    # --- DATES & TIME ---
    "DATE": "DATE",
    "DATE_DOB": "DOB",
    "DATE_TIME": "DATETIME",
    "DATETIME": "DATETIME",
    "TIME": "TIME",
    "BIRTHDAY": "DOB",
    "DOB": "DOB",
    "DATEOFBIRTH": "DOB",
    "DATE_OF_BIRTH": "DOB",
    "BIRTH_DATE": "DOB",
    "BIRTHDATE": "DOB",
    "BIRTH_YEAR": "DOB",
    "YEAR_OF_BIRTH": "DOB",
    "DATE_RANGE": "DATE",

    # --- AGE ---
    "AGE": "AGE",

    # --- LOCATIONS ---
    "ADDRESS": "ADDRESS",
    "STREET_ADDRESS": "ADDRESS",
    "STREET": "ADDRESS",
    "ZIP": "ZIP",
    "ZIPCODE": "ZIP",
    "ZIP_CODE": "ZIP",
    "LOCATION_ZIP": "ZIP",
    "POSTCODE": "ZIP",
    "CITY": "CITY",
    "STATE": "STATE",
    "COUNTRY": "COUNTRY",
    "COUNTY": "COUNTY",
    "GPS_COORDINATE": "GPS",
    "LATITUDE": "GPS",
    "LONGITUDE": "GPS",
    "COORDINATE": "GPS",
    "COORDINATES": "GPS",
    "GPE": "LOC",  # Geo-Political Entity (spaCy)
    "LOC": "LOC",
    "LOCATION-OTHER": "LOC",
    "LOCATION_OTHER": "LOC",
    "ROOM": "ROOM",
    "ROOM_NUMBER": "ROOM",

    # --- IDENTIFIERS - Government ---
    "SSN": "SSN",
    "SSN_PARTIAL": "SSN",
    "US_SSN": "SSN",
    "SOCIAL_SECURITY": "SSN",
    "SOCIALSECURITYNUMBER": "SSN",
    "UKNINUMBER": "NINO",  # UK National Insurance
    "DRIVER_LICENSE": "DL",
    "LICENSE": "LICENSE",
    "US_DRIVER_LICENSE": "DL",
    "DRIVERSLICENSE": "DL",
    "DRIVER_LICENSE_NUMBER": "DL",
    "STATE_ID": "STATEID",
    "STATEID": "STATEID",
    "PASSPORT": "PASSPORT",
    "US_PASSPORT": "PASSPORT",
    "PASSPORT_NUMBER": "PASSPORT",
    "PASSPORTNUMBER": "PASSPORT",
    "MILITARY_ID": "MILID",
    "EDIPI": "MILID",
    "DOD_ID": "MILID",

    # --- IDENTIFIERS - Medical ---
    "MRN": "MRN",
    "MEDICAL_RECORD": "MRN",
    "MEDICALRECORD": "MRN",
    "NPI": "NPI",
    "DEA": "DEA",
    "MEDICAL_LICENSE": "MEDLIC",
    "ENCOUNTER_ID": "ENCOUNTER",
    "ACCESSION_ID": "ACCESSION",
    "HEALTH_PLAN_ID": "PLAN",
    "HEALTHPLAN": "PLAN",
    "HEALTH_PLAN": "PLAN",
    "MEMBERID": "MEMBER",
    "MEMBER_ID": "MEMBER",
    "MEDICARE_ID": "MEDICARE",
    "PHARMACY_ID": "PHARMACY",
    "RX_NUMBER": "RX",
    "PRESCRIPTION": "RX",
    "SCRIPT": "RX",

    # --- IDENTIFIERS - Vehicle ---
    "VIN": "VIN",
    "VEHICLEVIN": "VIN",
    "VEHICLE_VIN": "VIN",
    "VEHICLE_IDENTIFICATION": "VIN",
    "VEHICLE": "VEHICLE",
    "LICENSE_PLATE": "PLATE",
    "VEHICLEVRM": "PLATE",
    "VEHICLE_PLATE": "PLATE",
    "PLATE_NUMBER": "PLATE",

    # --- CONTACT ---
    "PHONE": "PHONE",
    "PHONE_NUMBER": "PHONE",
    "PHONENUMBER": "PHONE",
    "US_PHONE_NUMBER": "PHONE",
    "TELEPHONE": "PHONE",
    "TEL": "PHONE",
    "MOBILE": "PHONE",
    "CELL": "PHONE",
    "EMAIL": "EMAIL",
    "EMAIL_ADDRESS": "EMAIL",
    "EMAILADDRESS": "EMAIL",
    "FAX": "FAX",
    "FAX_NUMBER": "FAX",
    "FAXNUMBER": "FAX",
    "PAGER": "PAGER",
    "PAGER_NUMBER": "PAGER",
    "URL": "URL",
    "USERNAME": "USER",

    # --- NETWORK & DEVICE ---
    "IP_ADDRESS": "IP",
    "IP": "IP",
    "IPADDRESS": "IP",
    "IPV4": "IP",
    "IPV6": "IP",
    "MAC_ADDRESS": "MAC",
    "MAC": "MAC",
    "MACADDRESS": "MAC",
    "DEVICE_ID": "DEVICE",
    "IMEI": "IMEI",
    "DEVICE": "DEVICE",
    "BIOID": "BIOID",
    "USERAGENT": "UA",
    "USER_AGENT": "UA",
    "BIOMETRIC_ID": "BIOMETRIC",
    "FINGERPRINT": "BIOMETRIC",
    "RETINAL": "BIOMETRIC",
    "IRIS": "BIOMETRIC",
    "VOICEPRINT": "BIOMETRIC",
    "DNA_ID": "BIOMETRIC",
    "IMAGE_ID": "IMGID",
    "PHOTO_ID": "IMGID",
    "DICOM_UID": "DICOM",
    "CERTIFICATE_NUMBER": "CERT",
    "CERTIFICATION": "CERT",
    "CLAIM_NUMBER": "CLAIM",

    # --- FINANCIAL - Traditional ---
    "CREDIT_CARD": "CC",
    "CREDIT_CARD_NUMBER": "CC",
    "CREDITCARDNUMBER": "CC",
    "CREDITCARD": "CC",
    "CC": "CC",
    "CREDIT_CARD_PARTIAL": "CC",
    "ACCOUNT_NUMBER": "ACCOUNT",
    "ACCOUNT": "ACCOUNT",
    "ACCOUNTNUMBER": "ACCOUNT",
    "BANK_ACCOUNT": "ACCOUNT",
    "IBAN": "IBAN",
    "IBAN_CODE": "IBAN",
    "IBANCODE": "IBAN",
    "ABA_ROUTING": "ABA",
    "ROUTING": "ABA",
    "ROUTING_NUMBER": "ABA",
    "BIC": "SWIFT",
    "SWIFT": "SWIFT",
    "SWIFT_BIC": "SWIFT",

    # --- FINANCIAL - Securities ---
    "CUSIP": "CUSIP",
    "ISIN": "ISIN",
    "SEDOL": "SEDOL",
    "FIGI": "FIGI",
    "LEI": "LEI",

    # --- CRYPTOCURRENCY ---
    "BITCOIN_ADDRESS": "BTC",
    "BITCOINADDRESS": "BTC",
    "ETHEREUM_ADDRESS": "ETH",
    "CRYPTO_SEED_PHRASE": "SEED",
    "SOLANA_ADDRESS": "SOL",
    "CARDANO_ADDRESS": "ADA",
    "LITECOIN_ADDRESS": "LTC",
    "DOGECOIN_ADDRESS": "DOGE",
    "XRP_ADDRESS": "XRP",

    # --- SECRETS - Cloud Providers ---
    "AWS_ACCESS_KEY": "AWS",
    "AWS_SECRET_KEY": "AWS",
    "AWS_SESSION_TOKEN": "AWS",
    "AZURE_STORAGE_KEY": "AZURE",
    "AZURE_CONNECTION_STRING": "AZURE",
    "AZURE_SAS_TOKEN": "AZURE",
    "GOOGLE_API_KEY": "GCP",
    "GOOGLE_OAUTH_ID": "GCP",
    "GOOGLE_OAUTH_SECRET": "GCP",
    "FIREBASE_KEY": "FIREBASE",

    # --- SECRETS - Code Repositories ---
    "GITHUB_TOKEN": "GITHUB",
    "GITLAB_TOKEN": "GITLAB",
    "NPM_TOKEN": "NPM",
    "PYPI_TOKEN": "PYPI",
    "NUGET_KEY": "NUGET",

    # --- SECRETS - Communication Services ---
    "SLACK_TOKEN": "SLACK",
    "SLACK_WEBHOOK": "SLACK",
    "DISCORD_TOKEN": "DISCORD",
    "DISCORD_WEBHOOK": "DISCORD",
    "TWILIO_ACCOUNT_SID": "TWILIO",
    "TWILIO_KEY": "TWILIO",
    "TWILIO_TOKEN": "TWILIO",
    "SENDGRID_KEY": "SENDGRID",
    "MAILCHIMP_KEY": "MAILCHIMP",

    # --- SECRETS - Payment & E-Commerce ---
    "STRIPE_KEY": "STRIPE",
    "SQUARE_TOKEN": "SQUARE",
    "SQUARE_SECRET": "SQUARE",
    "SHOPIFY_TOKEN": "SHOPIFY",
    "SHOPIFY_KEY": "SHOPIFY",
    "SHOPIFY_SECRET": "SHOPIFY",

    # --- SECRETS - Infrastructure ---
    "HEROKU_KEY": "HEROKU",
    "DATADOG_KEY": "DATADOG",
    "NEWRELIC_KEY": "NEWRELIC",
    "DATABASE_URL": "DBURL",

    # --- SECRETS - Authentication ---
    "PRIVATE_KEY": "PRIVKEY",
    "JWT": "JWT",
    "BASIC_AUTH": "AUTH",
    "BEARER_TOKEN": "TOKEN",
    "PASSWORD": "PASSWORD",
    "API_KEY": "APIKEY",
    "SECRET": "SECRET",

    # --- GOVERNMENT - Classification ---
    "CLASSIFICATION_LEVEL": "CLASS",
    "CLASSIFICATION_MARKING": "CLASS",
    "SCI_MARKING": "SCI",
    "DISSEMINATION_CONTROL": "DISSEM",

    # --- GOVERNMENT - Contracts & Identifiers ---
    "CAGE_CODE": "CAGE",
    "DUNS_NUMBER": "DUNS",
    "UEI": "UEI",
    "DOD_CONTRACT": "CONTRACT",
    "GSA_CONTRACT": "CONTRACT",

    # --- GOVERNMENT - Security & Export ---
    "CLEARANCE_LEVEL": "CLEARANCE",
    "ITAR_MARKING": "ITAR",
    "EAR_MARKING": "EAR",

    # --- PROFESSIONAL ---
    "PROFESSION": "PROFESSION",
    "OCCUPATION": "PROFESSION",
    "JOB": "PROFESSION",
    "JOB_TITLE": "PROFESSION",
    "JOBTITLE": "PROFESSION",
    "EMPLOYER": "EMPLOYER",

    # --- MEDICAL (context types - typically not tokenized) ---
    "DRUG": "DRUG",
    "MEDICATION": "MED",
    "LAB_TEST": "LAB",
    "DIAGNOSIS": "DX",
    "PROCEDURE": "PROC",
    "PAYER": "PAYER",

    # --- FACILITY / ORGANIZATION ---
    "FACILITY": "FACILITY",
    "HOSPITAL": "FACILITY",
    "ORG": "ORG",
    "ORGANIZATION": "ORG",
    "VENDOR": "VENDOR",
    "COMPANYNAME": "COMPANY",
    "COMPANY": "COMPANY",

    # --- STANFORD PHI-BERT SPECIFIC ---
    "ID": "ID",  # Generic identifier

    # --- PHYSICAL DESCRIPTORS ---
    "PHYSICAL_DESC": "PHYS",

    # --- DOCUMENT IDS ---
    "DOCUMENT_ID": "DOCID",
    "ID_NUMBER": "ID",

    # --- SHIPPING / LOGISTICS ---
    "TRACKING_NUMBER": "TRACKING",
    "SHIPMENT_ID": "SHIPMENT",

    # --- OTHER ---
    "UNIQUE_ID": "UID",
}

# NAME types for get_name_token_mappings (used by EntityRegistry for lookups)
NAME_TYPES: Set[str] = {
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    "PERSON",
}


class TokenStore:
    """
    Encrypted token storage backed by SQLite.

    Tokens map PHI values to placeholders like [PATIENT_1].
    Same value + same type = same token (case-insensitive hash match only).

    IMPORTANT: This class does NOT perform fuzzy matching.
    Entity identity decisions (e.g., "John Smith" == "Smith") are made
    by EntityRegistry. Use get_or_create_by_entity() with an entity_id
    from EntityRegistry for proper entity-aware token assignment.

    The old fuzzy matching logic was removed because it could incorrectly
    merge different people who share last names (e.g., "Maria Rodriguez"
    patient and "Carlos Rodriguez" doctor would get the same token).

    Scoping:
    - session_id: Required. Tokens are always scoped to a session.
    - conversation_id: Optional. When provided, tokens are isolated per
      conversation within the session. When None, tokens are session-wide.
    """

    def __init__(
        self,
        db: Database,
        keys: KeyManager,
        session_id: str,
        conversation_id: Optional[str] = None,
    ):
        """
        Initialize TokenStore.

        Args:
            db: Database instance
            keys: KeyManager for encryption
            session_id: Session identifier (required)
            conversation_id: Optional conversation identifier for per-conversation
                           token isolation. If None or empty, tokens are session-wide.
        """
        self._db = db
        self._keys = keys
        self._session_id = session_id
        # Use empty string for session-wide tokens (SQLite UNIQUE constraint compatibility)
        self._conversation_id = conversation_id if conversation_id else ""
        self._counters: Dict[str, int] = {}
        self._counter_lock = threading.Lock()  # Thread-safe counter access
        self._load_counters()

    @property
    def conversation_id(self) -> Optional[str]:
        """Get the conversation_id for this store (empty string for session-wide)."""
        return self._conversation_id if self._conversation_id else None

    def _load_counters(self) -> None:
        """Load token counters from database."""
        rows = self._db.fetchall("""
            SELECT token FROM tokens
            WHERE session_id = ? AND conversation_id = ?
        """, (self._session_id, self._conversation_id))

        for row in rows:
            token = row["token"]
            # Parse [PREFIX_N] format
            if token.startswith("[") and token.endswith("]"):
                inner = token[1:-1]
                parts = inner.rsplit("_", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    prefix = parts[0]
                    num = int(parts[1])
                    self._counters[prefix] = max(self._counters.get(prefix, 0), num)

    def _lookup_hash(self, value: str, entity_type: str) -> str:
        """Generate lookup hash for value+type (case-insensitive)."""
        normalized = f"{entity_type}:{value.lower().strip()}"
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]

    def _get_prefix(self, entity_type: str) -> str:
        """Get token prefix for entity type."""
        return TOKEN_PREFIX.get(entity_type, entity_type.upper())

    def _next_token(self, entity_type: str) -> str:
        """Generate next token for entity type (thread-safe)."""
        prefix = self._get_prefix(entity_type)
        with self._counter_lock:
            current = self._counters.get(prefix, 0)
            if current >= MAX_TOKEN_COUNT:
                raise RuntimeError(
                    f"Token counter exhausted for {prefix}. "
                    f"Maximum {MAX_TOKEN_COUNT} tokens per type per conversation."
                )
            self._counters[prefix] = current + 1
            return f"[{prefix}_{self._counters[prefix]}]"

    def add_variant(self, token: str, value: str, entity_type: str) -> None:
        """
        Add a variant mapping to an existing token.

        This allows fast hash lookup for the new variant in future calls.

        Args:
            token: Existing token like [NAME_1]
            value: New variant value (e.g., "Smith" when token has "John Smith")
            entity_type: Entity type
        """
        lookup = self._lookup_hash(value, entity_type)

        # Check if this exact variant already exists
        existing = self._db.fetchone("""
            SELECT token FROM tokens
            WHERE session_id = ? AND conversation_id = ? AND lookup_hash = ?
        """, (self._session_id, self._conversation_id, lookup))

        if existing:
            # Already have this variant
            return

        # Get the original row to copy safe_harbor pattern
        original = self._db.fetchone("""
            SELECT encrypted_safe_harbor FROM tokens
            WHERE session_id = ? AND conversation_id = ? AND token = ?
            LIMIT 1
        """, (self._session_id, self._conversation_id, token))

        # Encrypt the variant
        encrypted_value = self._keys.encrypt(value.encode("utf-8"))

        # Use token as safe harbor for variants (same as original behavior)
        encrypted_sh = original["encrypted_safe_harbor"] if original else self._keys.encrypt(token.encode("utf-8"))

        # Get entity_type from existing token if not provided
        if not entity_type:
            type_row = self._db.fetchone("""
                SELECT entity_type FROM tokens
                WHERE session_id = ? AND conversation_id = ? AND token = ?
                LIMIT 1
            """, (self._session_id, self._conversation_id, token))
            entity_type = type_row["entity_type"] if type_row else "NAME"

        # Insert variant as new row with same token
        self._db.execute("""
            INSERT OR IGNORE INTO tokens
            (session_id, conversation_id, token, entity_type, lookup_hash, encrypted_value, encrypted_safe_harbor)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (self._session_id, self._conversation_id, token, entity_type, lookup, encrypted_value, encrypted_sh))

        logger.debug(f"Added variant '{value}' for token {token}")

    # --- MAIN API ---
    def get_or_create(
        self,
        value: str,
        entity_type: str,
        safe_harbor_value: str = None
    ) -> str:
        """
        Get existing token or create new one (atomic).

        Uses exact hash lookup only. For entity-aware token assignment
        that handles partial names and variants, use get_or_create_by_entity()
        with an entity_id from EntityRegistry.

        Args:
            value: Original PHI value
            entity_type: Entity type (NAME_PATIENT, SSN, etc.)
            safe_harbor_value: Transformed value (optional)

        Returns:
            Token string like [PATIENT_1]

        Raises:
            ValueError: If value is empty or whitespace-only
            TypeError: If value is None
        """
        # Validate value
        if value is None:
            raise TypeError("Value cannot be None")
        if not isinstance(value, str):
            raise TypeError(f"Value must be a string, got {type(value).__name__}")
        if not value.strip():
            raise ValueError("Value cannot be empty or whitespace-only")

        lookup = self._lookup_hash(value, entity_type)

        with self._db.transaction():
            # Exact hash lookup
            row = self._db.conn.execute("""
                SELECT token FROM tokens
                WHERE session_id = ? AND conversation_id = ? AND lookup_hash = ?
            """, (self._session_id, self._conversation_id, lookup)).fetchone()

            if row:
                return row[0]

            # No match - create new token
            token = self._next_token(entity_type)

            # If no safe harbor value provided, use the token itself
            # (compliant per §164.514(c) - re-identification codes are permitted)
            if safe_harbor_value is None:
                safe_harbor_value = token

            encrypted_value = self._keys.encrypt(value.encode("utf-8"))
            encrypted_sh = self._keys.encrypt(safe_harbor_value.encode("utf-8"))

            # INSERT OR IGNORE handles race condition if another
            # transaction inserted between our SELECT and INSERT
            self._db.conn.execute("""
                INSERT OR IGNORE INTO tokens
                (session_id, conversation_id, token, entity_type, lookup_hash,
                 encrypted_value, encrypted_safe_harbor)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (self._session_id, self._conversation_id, token, entity_type, lookup,
                  encrypted_value, encrypted_sh))

            # If our insert was ignored (race condition), fetch the winner's token
            if self._db.conn.execute("SELECT changes()").fetchone()[0] == 0:
                row = self._db.conn.execute("""
                    SELECT token FROM tokens
                    WHERE session_id = ? AND conversation_id = ? AND lookup_hash = ?
                """, (self._session_id, self._conversation_id, lookup)).fetchone()
                # NOTE: We intentionally do NOT decrement the counter here.
                # The old code tried to "rollback" the counter, but this was racy:
                # if two threads both lose the INSERT race, both would decrement,
                # causing counter < actual max token number → potential collision.
                # Gaps in token numbering are fine; tokens just need to be unique.
                # The counter is reloaded from DB max on restart anyway.
                return row[0]

            return token

    def get(self, token: str, use_safe_harbor: bool = False) -> Optional[str]:
        """
        Get value for token.

        Args:
            token: Token string like [PATIENT_1]
            use_safe_harbor: Return Safe Harbor value instead of original.
                            Falls back to original if safe_harbor is NULL.

        Returns:
            Decrypted value or None if not found or decryption fails
        """
        # ORDER BY id ASC ensures we return the canonical (first-inserted) value,
        # not a variant that was added later via add_variant()
        row = self._db.fetchone("""
            SELECT encrypted_value, encrypted_safe_harbor FROM tokens
            WHERE session_id = ? AND conversation_id = ? AND token = ?
            ORDER BY id ASC
            LIMIT 1
        """, (self._session_id, self._conversation_id, token))

        if not row:
            return None

        # Choose value: safe_harbor if requested and available, else original
        if use_safe_harbor and row["encrypted_safe_harbor"]:
            encrypted = row["encrypted_safe_harbor"]
        elif row["encrypted_value"]:
            encrypted = row["encrypted_value"]
        else:
            return None

        # Log decryption failures
        try:
            return self._keys.decrypt(encrypted).decode("utf-8")
        except CryptoError as e:
            logger.error(
                f"Token decryption failed for {token}: {e}. "
                "This may indicate database corruption or key mismatch."
            )
            return None
        except UnicodeDecodeError as e:
            logger.error(
                f"Token decode failed for {token}: {e}. "
                "Decrypted data is not valid UTF-8."
            )
            return None

    def get_entry(self, token: str) -> Optional[TokenEntry]:
        """Get full token entry."""
        row = self._db.fetchone("""
            SELECT token, entity_type, encrypted_value, encrypted_safe_harbor, created_at
            FROM tokens WHERE session_id = ? AND conversation_id = ? AND token = ?
            LIMIT 1
        """, (self._session_id, self._conversation_id, token))

        if not row:
            return None

        return TokenEntry(
            token=row["token"],
            entity_type=row["entity_type"],
            original_value=self._keys.decrypt(row["encrypted_value"]).decode("utf-8"),
            safe_harbor_value=self._keys.decrypt(row["encrypted_safe_harbor"]).decode("utf-8"),
            session_id=self._session_id,
            created_at=datetime.fromisoformat(row["created_at"])
        )

    def list_tokens(self) -> List[str]:
        """List all unique tokens in session/conversation."""
        rows = self._db.fetchall("""
            SELECT DISTINCT token FROM tokens WHERE session_id = ? AND conversation_id = ? ORDER BY token
        """, (self._session_id, self._conversation_id))
        return [row["token"] for row in rows]

    def get_name_token_mappings(self) -> Dict[str, tuple]:
        """
        Get all NAME-type token mappings for EntityRegistry lookups.

        Returns:
            Dict mapping token -> (decrypted_value, entity_type)
            Only includes NAME, NAME_PATIENT, NAME_PROVIDER, NAME_RELATIVE types.
        """
        name_types = tuple(NAME_TYPES)
        placeholders = ",".join("?" * len(name_types))

        rows = self._db.fetchall(f"""
            SELECT token, entity_type, encrypted_value
            FROM tokens
            WHERE session_id = ? AND conversation_id = ? AND entity_type IN ({placeholders})
            ORDER BY id
        """, (self._session_id, self._conversation_id) + name_types)

        result = {}
        for row in rows:
            # Only keep first value per token (the original)
            if row["token"] in result:
                continue
            try:
                decrypted = self._keys.decrypt(row["encrypted_value"]).decode("utf-8")
                result[row["token"]] = (decrypted, row["entity_type"])
            except Exception as e:
                logger.warning(f"Failed to decrypt token {row['token']}: {e}")
                continue

        return result

    # --- PHASE 2: ENTITY-BASED API ---

    def get_or_create_by_entity(
        self,
        entity_id: str,
        value: str,
        entity_type: str,
        safe_harbor_value: str = None,
    ) -> str:
        """
        Get or create token using entity_id as the primary key (Phase 2).

        This is the new API for entity-based token lookup. The entity_id
        uniquely identifies a real-world entity across all its mentions,
        regardless of semantic role (patient, provider, etc.).

        Key difference from legacy get_or_create():
        - get_or_create uses (value, entity_type) as key → same person with
          different roles gets different tokens (LEGACY LIMITATION)
        - get_or_create_by_entity uses entity_id → same person always gets
          same token (RECOMMENDED)

        Args:
            entity_id: UUID from EntityResolver identifying the entity
            value: Original PHI value (canonical value of the entity)
            entity_type: Base entity type (NAME, SSN, etc.)
            safe_harbor_value: Transformed value for Safe Harbor mode

        Returns:
            Token string like [NAME_1]
        """
        if not entity_id:
            raise ValueError("entity_id cannot be empty")
        if not value or not value.strip():
            raise ValueError("value cannot be empty")

        # Create entity_id-based lookup hash
        entity_lookup = hashlib.sha256(
            f"entity:{entity_id}".encode("utf-8")
        ).hexdigest()[:32]

        with self._db.transaction():
            # Step 1: Check if we already have a token for this entity_id
            row = self._db.conn.execute("""
                SELECT token FROM tokens
                WHERE session_id = ? AND conversation_id = ? AND lookup_hash = ?
            """, (self._session_id, self._conversation_id, entity_lookup)).fetchone()

            if row:
                return row[0]

            # Step 2: Value-based fallback - check if we have a token for same value
            # This handles the case where entity_ids change between calls but the
            # underlying value is the same (e.g., "John Smith" should always get
            # the same token regardless of which entity_id was assigned)
            value_lookup = self._lookup_hash(value, entity_type)
            row = self._db.conn.execute("""
                SELECT token FROM tokens
                WHERE session_id = ? AND conversation_id = ? AND lookup_hash = ?
            """, (self._session_id, self._conversation_id, value_lookup)).fetchone()

            if row:
                # Found existing token by value - also register the new entity_id lookup
                # so future calls with this entity_id find it immediately
                existing_token = row[0]
                encrypted_value = self._keys.encrypt(value.encode("utf-8"))
                safe_harbor = safe_harbor_value if safe_harbor_value else existing_token
                encrypted_sh = self._keys.encrypt(safe_harbor.encode("utf-8"))

                # Insert alias entry with entity_id lookup hash pointing to same token
                self._db.conn.execute("""
                    INSERT OR IGNORE INTO tokens
                    (session_id, conversation_id, token, entity_type, lookup_hash,
                     encrypted_value, encrypted_safe_harbor)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (self._session_id, self._conversation_id, existing_token, entity_type,
                      entity_lookup, encrypted_value, encrypted_sh))

                return existing_token

            # Step 3: Create new token for this entity
            token = self._next_token(entity_type)

            if safe_harbor_value is None:
                safe_harbor_value = token

            encrypted_value = self._keys.encrypt(value.encode("utf-8"))
            encrypted_sh = self._keys.encrypt(safe_harbor_value.encode("utf-8"))

            # Insert with entity_id-based lookup hash
            self._db.conn.execute("""
                INSERT OR IGNORE INTO tokens
                (session_id, conversation_id, token, entity_type, lookup_hash,
                 encrypted_value, encrypted_safe_harbor)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (self._session_id, self._conversation_id, token, entity_type, entity_lookup,
                  encrypted_value, encrypted_sh))

            # Handle race condition
            if self._db.conn.execute("SELECT changes()").fetchone()[0] == 0:
                row = self._db.conn.execute("""
                    SELECT token FROM tokens
                    WHERE session_id = ? AND conversation_id = ? AND lookup_hash = ?
                """, (self._session_id, self._conversation_id, entity_lookup)).fetchone()
                # NOTE: Don't decrement counter - see comment in get_or_create()
                return row[0]

            # Also insert value-based lookup entry for future value-based lookups
            # This ensures the same value always gets the same token even if
            # the entity_id changes between calls
            self._db.conn.execute("""
                INSERT OR IGNORE INTO tokens
                (session_id, conversation_id, token, entity_type, lookup_hash,
                 encrypted_value, encrypted_safe_harbor)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (self._session_id, self._conversation_id, token, entity_type, value_lookup,
                  encrypted_value, encrypted_sh))

            logger.debug(f"Created token {token} for entity {entity_id[:8]}...")
            return token

    def get_entity_mappings(self) -> Dict[str, tuple]:
        """
        Get all entity mappings for cross-message persistence.

        This is used by EntityResolver to recognize previously-identified
        entities in new messages. Returns token -> (canonical_value, entity_type)
        for all NAME-type tokens.

        Note: The entity_id is hashed in lookup_hash, so we cannot easily
        reverse the mapping. Instead, we return all NAME-type token mappings
        which serves the same purpose for entity matching.

        A future schema upgrade could add an explicit entity_id column to
        enable true entity_id -> value lookup.

        Returns:
            Dict mapping token -> (decrypted_value, entity_type)
            Includes all NAME, NAME_PATIENT, NAME_PROVIDER, NAME_RELATIVE tokens.
        """
        return self.get_name_token_mappings()

    def register_entity_variant(
        self,
        entity_id: str,
        variant_value: str,
        entity_type: str,
    ) -> None:
        """
        Register a variant value for an entity.

        When EntityResolver groups multiple mentions into one entity,
        this method registers each variant for fast future lookup.

        Args:
            entity_id: UUID of the entity
            variant_value: A variant text (e.g., "Smith" for entity "John Smith")
            entity_type: Entity type
        """
        # First, get the token for this entity
        entity_lookup = hashlib.sha256(
            f"entity:{entity_id}".encode("utf-8")
        ).hexdigest()[:32]

        row = self._db.fetchone("""
            SELECT token FROM tokens
            WHERE session_id = ? AND conversation_id = ? AND lookup_hash = ?
        """, (self._session_id, self._conversation_id, entity_lookup))

        if not row:
            logger.warning(f"Cannot register variant - entity {entity_id[:8]} not found")
            return

        # Add the variant using the existing add_variant method
        self.add_variant(row["token"], variant_value, entity_type)

    def get_all_variants(self, token: str) -> List[str]:
        """
        Get all variant values stored for a token.

        Args:
            token: Token string like [NAME_1]

        Returns:
            List of all decrypted values (original + variants)
        """
        rows = self._db.fetchall("""
            SELECT encrypted_value FROM tokens
            WHERE session_id = ? AND conversation_id = ? AND token = ?
        """, (self._session_id, self._conversation_id, token))
        
        variants = []
        for row in rows:
            try:
                value = self._keys.decrypt(row["encrypted_value"]).decode("utf-8")
                variants.append(value)
            except Exception as e:
                logger.warning(f"Failed to decrypt variant for {token}: {e}")
        
        return variants

    def delete(self, token: str) -> bool:
        """Delete a token and all its variants. Returns True if deleted."""
        cursor = self._db.execute("""
            DELETE FROM tokens WHERE session_id = ? AND conversation_id = ? AND token = ?
        """, (self._session_id, self._conversation_id, token))
        return cursor.rowcount > 0

    def count(self) -> int:
        """Count unique tokens in session/conversation."""
        row = self._db.fetchone("""
            SELECT COUNT(DISTINCT token) as n FROM tokens WHERE session_id = ? AND conversation_id = ?
        """, (self._session_id, self._conversation_id))
        return row["n"] if row else 0

    def __len__(self) -> int:
        return self.count()
