"""
OpenLabels Vault - Encrypted storage for sensitive scan data.

Provides:
- Per-user encrypted vaults for storing sensitive spans
- Classification source tracking (Macie, Purview, OpenLabels scanner)
- Hash-chained audit logs (admin-encrypted)

Usage:
    from openlabels.vault import Vault

    # Get vault from authenticated session
    vault = session.get_vault()

    # Store scan results
    vault.store_scan_result(file_hash, file_path, spans, source="openlabels")

    # Retrieve for display (requires vault unlocked)
    result = vault.get_scan_result(file_hash)
    for span in result.spans:
        print(f"{span.entity_type}: {span.text}")

    # Get classification sources (metadata only, no sensitive text)
    sources = vault.get_classification_sources(file_hash)
"""

from .models import (
    VaultEntry,
    SensitiveSpan,
    ClassificationSource,
    Finding,
    AuditEntry,
    AuditAction,
)
from .vault import Vault
from .audit import AuditLog

__all__ = [
    "Vault",
    "VaultEntry",
    "SensitiveSpan",
    "ClassificationSource",
    "Finding",
    "AuditEntry",
    "AuditAction",
    "AuditLog",
]
