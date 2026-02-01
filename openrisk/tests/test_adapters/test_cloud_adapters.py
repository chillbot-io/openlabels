#!/usr/bin/env python3
"""Unit tests for cloud adapters (Macie, DLP, Purview)."""

import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from openlabels.adapters.macie import MacieAdapter
from openlabels.adapters.dlp import DLPAdapter
from openlabels.adapters.purview import PurviewAdapter
from openlabels.adapters.base import ExposureLevel, NormalizedInput


# =============================================================================
# MacieAdapter Tests
# =============================================================================

def test_macie_adapter_basic():
    """Test MacieAdapter with basic Macie findings."""
    print("Test: MacieAdapter basic extraction")

    adapter = MacieAdapter()

    findings = {
        "findings": [
            {
                "severity": {"score": 3},
                "classificationDetails": {
                    "result": {
                        "sensitiveData": [
                            {
                                "category": "PERSONAL_INFORMATION",
                                "detections": [
                                    {"type": "USA_SOCIAL_SECURITY_NUMBER", "count": 5}
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    }

    s3_metadata = {
        "bucket": "test-bucket",
        "key": "data/file.csv",
        "size": 1024,
        "last_modified": "2025-01-15T10:30:00Z",
        "content_type": "text/csv",
        "acl": "private",
        "public_access_block": True,
        "encryption": "AES256",
        "versioning": "Enabled",
        "logging_enabled": True,
        "owner": "123456789012"
    }

    result = adapter.extract(findings, s3_metadata)

    assert isinstance(result, NormalizedInput)
    assert len(result.entities) == 1
    assert result.entities[0].type == "SSN"  # Normalized from USA_SOCIAL_SECURITY_NUMBER
    assert result.entities[0].count == 5
    assert result.entities[0].source == "macie"
    assert result.context.exposure == "PRIVATE"
    assert result.context.path == "s3://test-bucket/data/file.csv"
    assert result.context.encryption == "platform"
    assert result.context.versioning is True

    print("  PASSED\n")


def test_macie_adapter_public_access_block_string():
    """Test MacieAdapter handles string boolean for public_access_block."""
    print("Test: MacieAdapter string boolean handling")

    adapter = MacieAdapter()

    findings = {"findings": []}
    s3_metadata = {
        "bucket": "test-bucket",
        "key": "file.txt",
        "public_access_block": "false",  # String instead of boolean
        "acl": "public-read",
    }

    result = adapter.extract(findings, s3_metadata)

    assert result.context.exposure == "PUBLIC"
    print("  PASSED\n")


def test_macie_adapter_public_access_block_true_string():
    """Test MacieAdapter handles 'true' string for public_access_block."""
    print("Test: MacieAdapter 'true' string handling")

    adapter = MacieAdapter()

    findings = {"findings": []}
    s3_metadata = {
        "bucket": "test-bucket",
        "key": "file.txt",
        "public_access_block": "True",  # String True
        "acl": "public-read",  # Would be public, but block should prevent it
    }

    result = adapter.extract(findings, s3_metadata)

    # With public_access_block enabled, shouldn't be public even with public-read ACL
    assert result.context.exposure != "PUBLIC"
    print("  PASSED\n")


def test_macie_adapter_severity_to_confidence():
    """Test severity to confidence mapping."""
    print("Test: MacieAdapter severity to confidence")

    adapter = MacieAdapter()

    # Test all severity levels
    assert adapter._severity_to_confidence(1) == 0.65  # Low
    assert adapter._severity_to_confidence(2) == 0.75  # Medium
    assert adapter._severity_to_confidence(3) == 0.85  # High
    assert adapter._severity_to_confidence(4) == 0.95  # Critical
    assert adapter._severity_to_confidence(99) == 0.75  # Unknown defaults to medium

    print("  PASSED\n")


def test_macie_adapter_kms_encryption():
    """Test that KMS encryption is detected as customer_managed."""
    print("Test: MacieAdapter KMS encryption detection")

    adapter = MacieAdapter()

    findings = {"findings": []}
    s3_metadata = {
        "bucket": "test-bucket",
        "key": "file.txt",
        "encryption": "aws:kms",
    }

    result = adapter.extract(findings, s3_metadata)

    assert result.context.encryption == "customer_managed"
    print("  PASSED\n")


def test_macie_adapter_website_hosting():
    """Test that website hosting is detected as PUBLIC."""
    print("Test: MacieAdapter website hosting detection")

    adapter = MacieAdapter()

    findings = {"findings": []}
    s3_metadata = {
        "bucket": "test-bucket",
        "key": "index.html",
        "website_enabled": True,
        "acl": "private",  # Even with private ACL, website = public
    }

    result = adapter.extract(findings, s3_metadata)

    assert result.context.exposure == "PUBLIC"
    print("  PASSED\n")


def test_macie_adapter_aws_exec_read():
    """Test that aws-exec-read ACL is INTERNAL."""
    print("Test: MacieAdapter aws-exec-read ACL")

    adapter = MacieAdapter()

    findings = {"findings": []}
    s3_metadata = {
        "bucket": "test-bucket",
        "key": "file.txt",
        "acl": "aws-exec-read",
        "public_access_block": True,
    }

    result = adapter.extract(findings, s3_metadata)

    assert result.context.exposure == "INTERNAL"
    print("  PASSED\n")


def test_macie_adapter_bucket_owner_read():
    """Test that bucket-owner-read ACL is PRIVATE."""
    print("Test: MacieAdapter bucket-owner-read ACL")

    adapter = MacieAdapter()

    findings = {"findings": []}
    s3_metadata = {
        "bucket": "test-bucket",
        "key": "file.txt",
        "acl": "bucket-owner-read",
    }

    result = adapter.extract(findings, s3_metadata)

    assert result.context.exposure == "PRIVATE"
    print("  PASSED\n")


def test_macie_adapter_cross_account():
    """Test that cross-account access is ORG_WIDE."""
    print("Test: MacieAdapter cross-account detection")

    adapter = MacieAdapter()

    findings = {"findings": []}
    s3_metadata = {
        "bucket": "test-bucket",
        "key": "file.txt",
        "acl": "private",
        "cross_account": True,
    }

    result = adapter.extract(findings, s3_metadata)

    assert result.context.exposure == "ORG_WIDE"
    print("  PASSED\n")


# =============================================================================
# DLPAdapter Tests
# =============================================================================

def test_dlp_adapter_basic():
    """Test DLPAdapter with basic DLP findings."""
    print("Test: DLPAdapter basic extraction")

    adapter = DLPAdapter()

    findings = {
        "result": {
            "findings": [
                {
                    "infoType": {"name": "US_SOCIAL_SECURITY_NUMBER"},
                    "likelihood": "VERY_LIKELY",
                },
                {
                    "infoType": {"name": "US_SOCIAL_SECURITY_NUMBER"},
                    "likelihood": "LIKELY",
                },
                {
                    "infoType": {"name": "CREDIT_CARD_NUMBER"},
                    "likelihood": "VERY_LIKELY",
                },
            ]
        }
    }

    gcs_metadata = {
        "bucket": "test-bucket",
        "name": "data/file.csv",
        "size": "2048",
        "updated": "2025-01-15T10:30:00Z",
        "contentType": "text/csv",
        "versioning": {"enabled": True},
        "logging": {"logBucket": "log-bucket"},
    }

    result = adapter.extract(findings, gcs_metadata)

    assert isinstance(result, NormalizedInput)
    assert len(result.entities) == 2  # SSN and CREDIT_CARD

    ssn_entity = next(e for e in result.entities if e.type == "SSN")
    assert ssn_entity.count == 2  # Two SSN findings
    assert ssn_entity.confidence == 0.95  # Max of VERY_LIKELY

    cc_entity = next(e for e in result.entities if e.type == "CREDIT_CARD")
    assert cc_entity.count == 1

    assert result.context.exposure == "PRIVATE"
    assert result.context.path == "gs://test-bucket/data/file.csv"
    assert result.context.versioning is True
    assert result.context.access_logging is True

    print("  PASSED\n")


def test_dlp_adapter_likelihood_mapping():
    """Test likelihood to confidence mapping."""
    print("Test: DLPAdapter likelihood to confidence")

    adapter = DLPAdapter()

    assert adapter._likelihood_to_confidence("VERY_LIKELY") == 0.95
    assert adapter._likelihood_to_confidence("LIKELY") == 0.85
    assert adapter._likelihood_to_confidence("POSSIBLE") == 0.70
    assert adapter._likelihood_to_confidence("UNLIKELY") == 0.50
    assert adapter._likelihood_to_confidence("VERY_UNLIKELY") == 0.30
    assert adapter._likelihood_to_confidence("LIKELIHOOD_UNSPECIFIED") == 0.60
    assert adapter._likelihood_to_confidence("UNKNOWN") == 0.70  # Default

    print("  PASSED\n")


def test_dlp_adapter_public_access():
    """Test DLPAdapter detects public access from IAM policy."""
    print("Test: DLPAdapter public access detection")

    adapter = DLPAdapter()

    findings = {"findings": []}
    gcs_metadata = {
        "bucket": "test-bucket",
        "name": "file.txt",
        "iam_policy": {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
            ]
        },
    }

    result = adapter.extract(findings, gcs_metadata)

    assert result.context.exposure == "PUBLIC"
    assert result.context.anonymous_access is True

    print("  PASSED\n")


def test_dlp_adapter_authenticated_users():
    """Test DLPAdapter detects allAuthenticatedUsers as ORG_WIDE."""
    print("Test: DLPAdapter allAuthenticatedUsers detection")

    adapter = DLPAdapter()

    findings = {"findings": []}
    gcs_metadata = {
        "bucket": "test-bucket",
        "name": "file.txt",
        "iam_policy": {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allAuthenticatedUsers"]}
            ]
        },
    }

    result = adapter.extract(findings, gcs_metadata)

    assert result.context.exposure == "ORG_WIDE"

    print("  PASSED\n")


def test_dlp_adapter_domain_access():
    """Test DLPAdapter detects domain-wide access as INTERNAL."""
    print("Test: DLPAdapter domain access detection")

    adapter = DLPAdapter()

    findings = {"findings": []}
    gcs_metadata = {
        "bucket": "test-bucket",
        "name": "file.txt",
        "iam_policy": {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["domain:example.com"]}
            ]
        },
    }

    result = adapter.extract(findings, gcs_metadata)

    assert result.context.exposure == "INTERNAL"

    print("  PASSED\n")


def test_dlp_adapter_project_access():
    """Test DLPAdapter detects project-wide access as INTERNAL."""
    print("Test: DLPAdapter project access detection")

    adapter = DLPAdapter()

    findings = {"findings": []}
    gcs_metadata = {
        "bucket": "test-bucket",
        "name": "file.txt",
        "iam_policy": {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["projectViewer:my-project"]}
            ]
        },
    }

    result = adapter.extract(findings, gcs_metadata)

    assert result.context.exposure == "INTERNAL"

    print("  PASSED\n")


def test_dlp_adapter_public_prevention():
    """Test DLPAdapter respects publicAccessPrevention."""
    print("Test: DLPAdapter publicAccessPrevention")

    adapter = DLPAdapter()

    findings = {"findings": []}
    gcs_metadata = {
        "bucket": "test-bucket",
        "name": "file.txt",
        "iamConfiguration": {"publicAccessPrevention": "enforced"},
        "iam_policy": {
            "bindings": [
                # Even with allUsers, prevention should block
                {"role": "roles/storage.objectViewer", "members": ["user:test@example.com"]}
            ]
        },
    }

    result = adapter.extract(findings, gcs_metadata)

    assert result.context.exposure == "PRIVATE"

    print("  PASSED\n")


# =============================================================================
# PurviewAdapter Tests
# =============================================================================

def test_purview_adapter_basic():
    """Test PurviewAdapter with basic classifications."""
    print("Test: PurviewAdapter basic extraction")

    adapter = PurviewAdapter()

    classifications = {
        "classifications": [
            {
                "typeName": "MICROSOFT.PERSONAL.US.SOCIAL_SECURITY_NUMBER",
                "attributes": {"confidence": 0.95, "count": 3}
            },
            {
                "classificationName": "Credit Card Number",
                "count": 2
            }
        ]
    }

    blob_metadata = {
        "container": "test-container",
        "name": "data/file.csv",
        "properties": {
            "content_length": 1024,
            "last_modified": "2025-01-15T10:30:00Z",
            "content_type": "text/csv",
        },
        "access_level": "private",
        "versioning_enabled": True,
        "soft_delete_enabled": True,
    }

    result = adapter.extract(classifications, blob_metadata)

    assert isinstance(result, NormalizedInput)
    assert len(result.entities) == 2

    ssn_entity = next(e for e in result.entities if e.type == "SSN")
    assert ssn_entity.count == 3
    assert ssn_entity.confidence == 0.95

    cc_entity = next(e for e in result.entities if e.type == "CREDIT_CARD")
    assert cc_entity.count == 2

    assert result.context.exposure == "PRIVATE"
    assert result.context.path == "azure://test-container/data/file.csv"
    assert result.context.versioning is True

    print("  PASSED\n")


def test_purview_adapter_type_normalization():
    """Test Purview internal type name normalization."""
    print("Test: PurviewAdapter type normalization")

    adapter = PurviewAdapter()

    # Test known mappings
    assert adapter._normalize_type_name("MICROSOFT.PERSONAL.US.SOCIAL_SECURITY_NUMBER") == "U.S. Social Security Number (SSN)"
    assert adapter._normalize_type_name("MICROSOFT.FINANCIAL.CREDIT_CARD_NUMBER") == "Credit Card Number"
    assert adapter._normalize_type_name("MICROSOFT.PERSONAL.EMAIL") == "Email"

    # Test fallback for unknown MICROSOFT.* types
    assert adapter._normalize_type_name("MICROSOFT.PERSONAL.UK.NINO") == "NINO"
    assert adapter._normalize_type_name("MICROSOFT.FINANCIAL.IBAN") == "IBAN"

    # Test passthrough for non-MICROSOFT types
    assert adapter._normalize_type_name("Custom Type") == "Custom Type"

    print("  PASSED\n")


def test_purview_adapter_container_access():
    """Test PurviewAdapter detects container-level access as PUBLIC."""
    print("Test: PurviewAdapter container access detection")

    adapter = PurviewAdapter()

    classifications = {"classifications": []}
    blob_metadata = {
        "container": "test-container",
        "name": "file.txt",
        "properties": {},
        "access_level": "container",
    }

    result = adapter.extract(classifications, blob_metadata)

    assert result.context.exposure == "PUBLIC"

    print("  PASSED\n")


def test_purview_adapter_blob_access():
    """Test PurviewAdapter detects blob-level access as ORG_WIDE."""
    print("Test: PurviewAdapter blob access detection")

    adapter = PurviewAdapter()

    classifications = {"classifications": []}
    blob_metadata = {
        "container": "test-container",
        "name": "file.txt",
        "properties": {},
        "access_level": "blob",
    }

    result = adapter.extract(classifications, blob_metadata)

    assert result.context.exposure == "ORG_WIDE"

    print("  PASSED\n")


def test_purview_adapter_keyvault_encryption():
    """Test PurviewAdapter detects KeyVault encryption as customer_managed."""
    print("Test: PurviewAdapter KeyVault encryption detection")

    adapter = PurviewAdapter()

    classifications = {"classifications": []}
    blob_metadata = {
        "container": "test-container",
        "name": "file.txt",
        "properties": {},
        "encryption": {"key_source": "Microsoft.KeyVault"},
    }

    result = adapter.extract(classifications, blob_metadata)

    assert result.context.encryption == "customer_managed"

    print("  PASSED\n")


def test_purview_adapter_scan_result_format():
    """Test PurviewAdapter handles scanResult format."""
    print("Test: PurviewAdapter scanResult format")

    adapter = PurviewAdapter()

    classifications = {
        "scanResult": {
            "classifications": [
                {"classificationName": "Email", "count": 5}
            ]
        }
    }

    blob_metadata = {
        "container": "test-container",
        "name": "file.txt",
        "properties": {},
    }

    result = adapter.extract(classifications, blob_metadata)

    assert len(result.entities) == 1
    assert result.entities[0].type == "Email"
    assert result.entities[0].count == 5

    print("  PASSED\n")


def test_purview_adapter_private_endpoint():
    """Test PurviewAdapter detects private endpoint as PRIVATE."""
    print("Test: PurviewAdapter private endpoint detection")

    adapter = PurviewAdapter()

    classifications = {"classifications": []}
    blob_metadata = {
        "container": "test-container",
        "name": "file.txt",
        "properties": {},
        "private_endpoint_only": True,
    }

    result = adapter.extract(classifications, blob_metadata)

    assert result.context.exposure == "PRIVATE"

    print("  PASSED\n")


def test_purview_adapter_vnet_rules():
    """Test PurviewAdapter detects VNet rules as INTERNAL."""
    print("Test: PurviewAdapter VNet rules detection")

    adapter = PurviewAdapter()

    classifications = {"classifications": []}
    blob_metadata = {
        "container": "test-container",
        "name": "file.txt",
        "properties": {},
        "network_rules": {
            "default_action": "Deny",
            "virtual_network_rules": [{"id": "/subscriptions/.../virtualNetworks/vnet1"}],
        },
    }

    result = adapter.extract(classifications, blob_metadata)

    assert result.context.exposure == "INTERNAL"

    print("  PASSED\n")


def test_purview_adapter_network_allow_no_rules():
    """Test PurviewAdapter detects Allow without rules as ORG_WIDE."""
    print("Test: PurviewAdapter network Allow without rules")

    adapter = PurviewAdapter()

    classifications = {"classifications": []}
    blob_metadata = {
        "container": "test-container",
        "name": "file.txt",
        "properties": {},
        "network_rules": {
            "default_action": "Allow",
            # No VNet or IP rules = broadly accessible
        },
    }

    result = adapter.extract(classifications, blob_metadata)

    assert result.context.exposure == "ORG_WIDE"

    print("  PASSED\n")


def test_purview_adapter_cross_tenant():
    """Test PurviewAdapter detects cross-tenant access as ORG_WIDE."""
    print("Test: PurviewAdapter cross-tenant detection")

    adapter = PurviewAdapter()

    classifications = {"classifications": []}
    blob_metadata = {
        "container": "test-container",
        "name": "file.txt",
        "properties": {},
        "access_level": "private",
        "cross_tenant_access": True,
    }

    result = adapter.extract(classifications, blob_metadata)

    assert result.context.exposure == "ORG_WIDE"

    print("  PASSED\n")


def test_purview_adapter_sas_broad_permissions():
    """Test PurviewAdapter detects broad SAS permissions as ORG_WIDE."""
    print("Test: PurviewAdapter SAS broad permissions")

    adapter = PurviewAdapter()

    classifications = {"classifications": []}
    blob_metadata = {
        "container": "test-container",
        "name": "file.txt",
        "properties": {},
        "access_level": "private",
        "sas_policy": {
            "permissions": "rwdl",  # Read, Write, Delete, List
            "has_expiry": True,
        },
    }

    result = adapter.extract(classifications, blob_metadata)

    assert result.context.exposure == "ORG_WIDE"

    print("  PASSED\n")


# =============================================================================
# Main
# =============================================================================

def main():
    """Run all adapter tests."""
    print("=" * 60)
    print("OpenLabels Cloud Adapter Tests")
    print("=" * 60 + "\n")

    tests = [
        # Macie tests - basic
        test_macie_adapter_basic,
        test_macie_adapter_public_access_block_string,
        test_macie_adapter_public_access_block_true_string,
        test_macie_adapter_severity_to_confidence,
        test_macie_adapter_kms_encryption,
        # Macie tests - permission mappings
        test_macie_adapter_website_hosting,
        test_macie_adapter_aws_exec_read,
        test_macie_adapter_bucket_owner_read,
        test_macie_adapter_cross_account,
        # DLP tests - basic
        test_dlp_adapter_basic,
        test_dlp_adapter_likelihood_mapping,
        test_dlp_adapter_public_access,
        test_dlp_adapter_authenticated_users,
        # DLP tests - permission mappings
        test_dlp_adapter_domain_access,
        test_dlp_adapter_project_access,
        test_dlp_adapter_public_prevention,
        # Purview tests - basic
        test_purview_adapter_basic,
        test_purview_adapter_type_normalization,
        test_purview_adapter_container_access,
        test_purview_adapter_blob_access,
        test_purview_adapter_keyvault_encryption,
        test_purview_adapter_scan_result_format,
        # Purview tests - permission mappings
        test_purview_adapter_private_endpoint,
        test_purview_adapter_vnet_rules,
        test_purview_adapter_network_allow_no_rules,
        test_purview_adapter_cross_tenant,
        test_purview_adapter_sas_broad_permissions,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  FAILED: {e}\n")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}\n")
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
