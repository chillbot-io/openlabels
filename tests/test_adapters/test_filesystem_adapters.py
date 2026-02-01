#!/usr/bin/env python3
"""Unit tests for filesystem adapters (NTFS, NFS, M365)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from openlabels.adapters.ntfs import NTFSAdapter
from openlabels.adapters.nfs import NFSAdapter
from openlabels.adapters.m365 import M365Adapter
from openlabels.adapters.base import NormalizedInput


# =============================================================================
# NTFSAdapter Tests
# =============================================================================

def test_ntfs_adapter_private_owner():
    """Test NTFS with owner-only access."""
    print("Test: NTFSAdapter owner-only access")

    adapter = NTFSAdapter()

    acl_data = {
        "owner": "DOMAIN\\jsmith",
        "aces": [
            {
                "trustee": "DOMAIN\\jsmith",
                "type": "allow",
                "permissions": ["full_control"],
                "inherited": False,
            }
        ],
    }

    file_meta = {
        "path": "\\\\server\\share\\file.txt",
        "size": 1024,
    }

    result = adapter.extract(acl_data, file_meta)

    assert isinstance(result, NormalizedInput)
    assert result.context.exposure == "PRIVATE"

    print("  PASSED\n")


def test_ntfs_adapter_domain_users():
    """Test NTFS with Domain Users access (INTERNAL)."""
    print("Test: NTFSAdapter Domain Users access")

    adapter = NTFSAdapter()

    acl_data = {
        "owner": "DOMAIN\\admin",
        "aces": [
            {
                "trustee": "DOMAIN\\Domain Users",
                "type": "allow",
                "permissions": ["read"],
                "inherited": True,
            }
        ],
    }

    file_meta = {"path": "\\\\server\\share\\file.txt"}

    result = adapter.extract(acl_data, file_meta)

    assert result.context.exposure == "INTERNAL"

    print("  PASSED\n")


def test_ntfs_adapter_builtin_users():
    """Test NTFS with BUILTIN\\Users access (ORG_WIDE)."""
    print("Test: NTFSAdapter BUILTIN\\Users access")

    adapter = NTFSAdapter()

    acl_data = {
        "owner": "DOMAIN\\admin",
        "aces": [
            {
                "trustee": "BUILTIN\\Users",
                "type": "allow",
                "permissions": ["read"],
                "inherited": True,
            }
        ],
    }

    file_meta = {"path": "\\\\server\\share\\file.txt"}

    result = adapter.extract(acl_data, file_meta)

    assert result.context.exposure == "ORG_WIDE"

    print("  PASSED\n")


def test_ntfs_adapter_anonymous_logon():
    """Test NTFS with Anonymous Logon (PUBLIC)."""
    print("Test: NTFSAdapter Anonymous Logon access")

    adapter = NTFSAdapter()

    acl_data = {
        "owner": "DOMAIN\\admin",
        "aces": [
            {
                "trustee": "Anonymous Logon",
                "sid": "S-1-5-7",
                "type": "allow",
                "permissions": ["read"],
                "inherited": False,
            }
        ],
    }

    file_meta = {"path": "\\\\server\\share\\file.txt"}

    result = adapter.extract(acl_data, file_meta)

    assert result.context.exposure == "PUBLIC"
    assert result.context.anonymous_access is True

    print("  PASSED\n")


def test_ntfs_adapter_everyone_share():
    """Test NTFS with Everyone Full Control on share (PUBLIC)."""
    print("Test: NTFSAdapter Everyone share permission")

    adapter = NTFSAdapter()

    acl_data = {
        "owner": "DOMAIN\\admin",
        "aces": [
            {
                "trustee": "DOMAIN\\Users",
                "type": "allow",
                "permissions": ["read"],
            }
        ],
        "share_permissions": [
            {
                "trustee": "Everyone",
                "permissions": ["full_control"],
            }
        ],
    }

    file_meta = {"path": "\\\\server\\share\\file.txt"}

    result = adapter.extract(acl_data, file_meta)

    assert result.context.exposure == "PUBLIC"

    print("  PASSED\n")


def test_ntfs_adapter_most_permissive_wins():
    """Test NTFS uses most permissive ACE."""
    print("Test: NTFSAdapter most permissive wins")

    adapter = NTFSAdapter()

    acl_data = {
        "owner": "DOMAIN\\admin",
        "aces": [
            {
                "trustee": "DOMAIN\\admin",
                "type": "allow",
                "permissions": ["full_control"],  # PRIVATE
            },
            {
                "trustee": "DOMAIN\\Domain Users",
                "type": "allow",
                "permissions": ["read"],  # INTERNAL
            },
            {
                "trustee": "BUILTIN\\Users",
                "type": "allow",
                "permissions": ["read"],  # ORG_WIDE - should win
            },
        ],
    }

    file_meta = {"path": "\\\\server\\share\\file.txt"}

    result = adapter.extract(acl_data, file_meta)

    assert result.context.exposure == "ORG_WIDE"

    print("  PASSED\n")


# =============================================================================
# NFSAdapter Tests
# =============================================================================

def test_nfs_adapter_single_host():
    """Test NFS with single host export (PRIVATE)."""
    print("Test: NFSAdapter single host export")

    adapter = NFSAdapter()

    export_config = {
        "export_path": "/data/private",
        "clients": [
            {
                "host": "192.168.1.100",
                "options": ["rw", "sync", "root_squash"],
            }
        ],
    }

    file_meta = {
        "path": "/data/private/file.txt",
        "mode": "0644",
        "size": 1024,
    }

    result = adapter.extract(export_config, file_meta)

    assert isinstance(result, NormalizedInput)
    assert result.context.exposure == "PRIVATE"

    print("  PASSED\n")


def test_nfs_adapter_subnet_24():
    """Test NFS with /24 subnet export (INTERNAL)."""
    print("Test: NFSAdapter /24 subnet export")

    adapter = NFSAdapter()

    export_config = {
        "export_path": "/data/team",
        "clients": [
            {
                "host": "10.0.0.0/24",
                "options": ["rw", "sync", "root_squash"],
            }
        ],
    }

    file_meta = {"path": "/data/team/file.txt", "mode": "0644"}

    result = adapter.extract(export_config, file_meta)

    assert result.context.exposure == "INTERNAL"

    print("  PASSED\n")


def test_nfs_adapter_kerberos():
    """Test NFS with Kerberos auth (INTERNAL)."""
    print("Test: NFSAdapter Kerberos auth")

    adapter = NFSAdapter()

    export_config = {
        "export_path": "/data/secure",
        "clients": [
            {
                "host": "10.0.0.0/16",  # Large subnet would be ORG_WIDE
                "options": ["rw", "sync", "sec=krb5p"],  # But Kerberos caps it
            }
        ],
    }

    file_meta = {"path": "/data/secure/file.txt"}

    result = adapter.extract(export_config, file_meta)

    assert result.context.exposure == "INTERNAL"
    assert result.context.encryption == "platform"  # krb5p = encrypted

    print("  PASSED\n")


def test_nfs_adapter_wildcard_export():
    """Test NFS with wildcard export (PUBLIC)."""
    print("Test: NFSAdapter wildcard export")

    adapter = NFSAdapter()

    export_config = {
        "export_path": "/data/public",
        "clients": [
            {
                "host": "*",
                "options": ["ro", "sync"],
            }
        ],
    }

    file_meta = {"path": "/data/public/file.txt", "mode": "0755"}

    result = adapter.extract(export_config, file_meta)

    assert result.context.exposure == "PUBLIC"

    print("  PASSED\n")


def test_nfs_adapter_no_root_squash():
    """Test NFS with no_root_squash (elevates to ORG_WIDE)."""
    print("Test: NFSAdapter no_root_squash")

    adapter = NFSAdapter()

    export_config = {
        "export_path": "/data/admin",
        "clients": [
            {
                "host": "10.0.0.0/24",  # Would be INTERNAL
                "options": ["rw", "sync", "no_root_squash"],  # Elevates risk
            }
        ],
    }

    file_meta = {"path": "/data/admin/file.txt"}

    result = adapter.extract(export_config, file_meta)

    assert result.context.exposure == "ORG_WIDE"

    print("  PASSED\n")


def test_nfs_adapter_insecure_option():
    """Test NFS with insecure option on broad export (PUBLIC)."""
    print("Test: NFSAdapter insecure option")

    adapter = NFSAdapter()

    export_config = {
        "export_path": "/data/risky",
        "clients": [
            {
                "host": "10.0.0.0/8",  # ORG_WIDE
                "options": ["rw", "insecure"],  # Elevates to PUBLIC
            }
        ],
    }

    file_meta = {"path": "/data/risky/file.txt"}

    result = adapter.extract(export_config, file_meta)

    assert result.context.exposure == "PUBLIC"

    print("  PASSED\n")


def test_nfs_adapter_most_permissive_wins():
    """Test NFS uses most permissive client."""
    print("Test: NFSAdapter most permissive wins")

    adapter = NFSAdapter()

    export_config = {
        "export_path": "/data/mixed",
        "clients": [
            {
                "host": "192.168.1.100",  # PRIVATE
                "options": ["rw", "root_squash"],
            },
            {
                "host": "10.0.0.0/24",  # INTERNAL
                "options": ["ro", "root_squash"],
            },
            {
                "host": "*",  # PUBLIC - should win
                "options": ["ro"],
            },
        ],
    }

    file_meta = {"path": "/data/mixed/file.txt"}

    result = adapter.extract(export_config, file_meta)

    assert result.context.exposure == "PUBLIC"

    print("  PASSED\n")


# =============================================================================
# M365Adapter Tests
# =============================================================================

def test_m365_adapter_specific_users():
    """Test M365 with specific user permissions (PRIVATE)."""
    print("Test: M365Adapter specific user permissions")

    adapter = M365Adapter()

    permissions = {
        "direct_permissions": [
            {
                "grantedTo": {"user": {"email": "user@company.com"}},
                "roles": ["read"],
            }
        ],
        "sharing_links": [],
    }

    item_meta = {
        "name": "document.docx",
        "webUrl": "https://company.sharepoint.com/sites/team/doc.docx",
        "size": 10240,
    }

    result = adapter.extract(permissions, item_meta)

    assert isinstance(result, NormalizedInput)
    assert result.context.exposure == "PRIVATE"

    print("  PASSED\n")


def test_m365_adapter_org_link():
    """Test M365 with organization sharing link (ORG_WIDE)."""
    print("Test: M365Adapter organization link")

    adapter = M365Adapter()

    permissions = {
        "direct_permissions": [],
        "sharing_links": [
            {
                "type": "view",
                "scope": "organization",
                "requiresSignIn": True,
            }
        ],
    }

    item_meta = {"name": "report.xlsx", "size": 5120}

    result = adapter.extract(permissions, item_meta)

    assert result.context.exposure == "ORG_WIDE"

    print("  PASSED\n")


def test_m365_adapter_anonymous_link():
    """Test M365 with anonymous sharing link (PUBLIC)."""
    print("Test: M365Adapter anonymous link")

    adapter = M365Adapter()

    permissions = {
        "direct_permissions": [],
        "sharing_links": [
            {
                "type": "view",
                "scope": "anonymous",
                "hasPassword": False,
                "expirationDateTime": None,
            }
        ],
    }

    item_meta = {"name": "public.pdf", "size": 2048}

    result = adapter.extract(permissions, item_meta)

    assert result.context.exposure == "PUBLIC"
    assert result.context.anonymous_access is True

    print("  PASSED\n")


def test_m365_adapter_guest_user():
    """Test M365 with external guest user (ORG_WIDE)."""
    print("Test: M365Adapter guest user access")

    adapter = M365Adapter()

    permissions = {
        "direct_permissions": [
            {
                "grantedTo": {
                    "user": {
                        "email": "guest#ext#@company.onmicrosoft.com",
                        "userType": "Guest",
                    }
                },
                "roles": ["read"],
            }
        ],
        "sharing_links": [],
    }

    item_meta = {"name": "shared.docx", "size": 1024}

    result = adapter.extract(permissions, item_meta)

    assert result.context.exposure == "ORG_WIDE"
    assert result.context.cross_account_access is True

    print("  PASSED\n")


def test_m365_adapter_security_group():
    """Test M365 with security group (INTERNAL)."""
    print("Test: M365Adapter security group")

    adapter = M365Adapter()

    permissions = {
        "direct_permissions": [
            {
                "grantedTo": {
                    "group": {"displayName": "Marketing Team"}
                },
                "roles": ["read", "write"],
            }
        ],
        "sharing_links": [],
    }

    item_meta = {"name": "marketing.pptx", "size": 51200}

    result = adapter.extract(permissions, item_meta)

    assert result.context.exposure == "INTERNAL"

    print("  PASSED\n")


def test_m365_adapter_sensitivity_label():
    """Test M365 with sensitivity label."""
    print("Test: M365Adapter sensitivity label")

    adapter = M365Adapter()

    permissions = {
        "direct_permissions": [],
        "sharing_links": [],
        "sensitivity_label": "Confidential",
    }

    item_meta = {
        "name": "secret.docx",
        "sensitivity_label": "Confidential",
    }

    result = adapter.extract(permissions, item_meta)

    assert result.context.has_classification is True
    assert result.context.classification_source == "m365"

    print("  PASSED\n")


def test_m365_adapter_most_permissive_wins():
    """Test M365 uses most permissive permission."""
    print("Test: M365Adapter most permissive wins")

    adapter = M365Adapter()

    permissions = {
        "direct_permissions": [
            {
                "grantedTo": {"user": {"email": "user@company.com"}},
                "roles": ["read"],  # PRIVATE
            },
            {
                "grantedTo": {"group": {"displayName": "IT Team"}},
                "roles": ["read"],  # INTERNAL
            },
        ],
        "sharing_links": [
            {
                "type": "view",
                "scope": "organization",  # ORG_WIDE
            },
            {
                "type": "view",
                "scope": "anyone",  # PUBLIC - should win
                "hasPassword": False,
            },
        ],
    }

    item_meta = {"name": "widely-shared.pdf", "size": 1024}

    result = adapter.extract(permissions, item_meta)

    assert result.context.exposure == "PUBLIC"

    print("  PASSED\n")


# =============================================================================
# Main
# =============================================================================

def main():
    """Run all filesystem adapter tests."""
    print("=" * 60)
    print("OpenLabels Filesystem Adapter Tests")
    print("=" * 60 + "\n")

    tests = [
        # NTFS tests
        test_ntfs_adapter_private_owner,
        test_ntfs_adapter_domain_users,
        test_ntfs_adapter_builtin_users,
        test_ntfs_adapter_anonymous_logon,
        test_ntfs_adapter_everyone_share,
        test_ntfs_adapter_most_permissive_wins,
        # NFS tests
        test_nfs_adapter_single_host,
        test_nfs_adapter_subnet_24,
        test_nfs_adapter_kerberos,
        test_nfs_adapter_wildcard_export,
        test_nfs_adapter_no_root_squash,
        test_nfs_adapter_insecure_option,
        test_nfs_adapter_most_permissive_wins,
        # M365 tests
        test_m365_adapter_specific_users,
        test_m365_adapter_org_link,
        test_m365_adapter_anonymous_link,
        test_m365_adapter_guest_user,
        test_m365_adapter_security_group,
        test_m365_adapter_sensitivity_label,
        test_m365_adapter_most_permissive_wins,
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
