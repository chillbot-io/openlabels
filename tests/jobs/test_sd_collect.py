"""Tests for security descriptor collection (sd_collect.py)."""

import os
import stat
import tempfile
from pathlib import Path

import pytest

from openlabels.jobs.sd_collect import (
    SDInfo,
    _collect_batch_sync,
    collect_posix_sd,
    collect_sd,
)


class TestSDInfoHashing:

    def test_identical_sds_produce_same_hash(self):
        a = SDInfo("root", "root", "0o755", None, False, False, False)
        b = SDInfo("root", "root", "0o755", None, False, False, False)
        assert a.sd_hash() == b.sd_hash()

    def test_different_owner_produces_different_hash(self):
        a = SDInfo("root", "root", "0o755", None, False, False, False)
        b = SDInfo("nobody", "root", "0o755", None, False, False, False)
        assert a.sd_hash() != b.sd_hash()

    def test_different_group_produces_different_hash(self):
        a = SDInfo("root", "root", "0o755", None, False, False, False)
        b = SDInfo("root", "wheel", "0o755", None, False, False, False)
        assert a.sd_hash() != b.sd_hash()

    def test_different_dacl_produces_different_hash(self):
        a = SDInfo("root", "root", "0o755", None, False, False, False)
        b = SDInfo("root", "root", "0o700", None, False, False, False)
        assert a.sd_hash() != b.sd_hash()

    def test_world_accessible_flag_changes_hash(self):
        a = SDInfo("root", "root", "0o755", None, False, False, False)
        b = SDInfo("root", "root", "0o755", None, True, False, False)
        assert a.sd_hash() != b.sd_hash()

    def test_authenticated_users_flag_changes_hash(self):
        a = SDInfo("root", "root", "0o755", None, False, False, False)
        b = SDInfo("root", "root", "0o755", None, False, True, False)
        assert a.sd_hash() != b.sd_hash()

    def test_custom_acl_does_not_affect_hash(self):
        """custom_acl is NOT included in canonical_bytes — only in DB metadata."""
        a = SDInfo("root", "root", "0o755", None, False, False, False)
        b = SDInfo("root", "root", "0o755", None, False, False, True)
        # custom_acl is not in canonical form, so hashes are equal
        assert a.sd_hash() == b.sd_hash()

    def test_permissions_json_does_not_affect_hash(self):
        """permissions_json is stored for display, not included in hash."""
        a = SDInfo("root", "root", "0o755", {"uid": 0}, False, False, False)
        b = SDInfo("root", "root", "0o755", {"uid": 1000}, False, False, False)
        assert a.sd_hash() == b.sd_hash()

    def test_hash_is_32_bytes(self):
        sd = SDInfo("root", "root", "0o755", None, False, False, False)
        assert len(sd.sd_hash()) == 32

    def test_canonical_bytes_is_valid_json(self):
        import json

        sd = SDInfo("root", "root", "0o755", None, True, False, False)
        parsed = json.loads(sd.canonical_bytes().decode())
        assert parsed["owner"] == "root"
        assert parsed["group"] == "root"
        assert parsed["dacl"] == "0o755"
        assert parsed["wa"] is True
        assert parsed["au"] is False

    def test_canonical_bytes_are_deterministic_across_calls(self):
        sd = SDInfo("root", "root", "0o755", None, False, False, False)
        assert sd.canonical_bytes() == sd.canonical_bytes()

    def test_none_fields_hash_consistently(self):
        a = SDInfo(None, None, None, None, False, False, False)
        b = SDInfo(None, None, None, None, False, False, False)
        assert a.sd_hash() == b.sd_hash()
        assert len(a.sd_hash()) == 32


@pytest.mark.skipif(os.name == "nt", reason="POSIX-specific")
class TestCollectPosixSD:

    def test_collects_uid_gid_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chmod(tmpdir, 0o755)
            sd = collect_posix_sd(tmpdir)

            assert sd is not None
            assert sd.owner_sid is not None
            assert sd.group_sid is not None
            assert sd.dacl_sddl is not None
            assert sd.dacl_sddl.startswith("0o")

    def test_world_accessible_for_other_readable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chmod(tmpdir, 0o755)
            sd = collect_posix_sd(tmpdir)

            assert sd is not None
            assert sd.world_accessible is True

    def test_not_world_accessible_for_owner_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chmod(tmpdir, 0o700)
            sd = collect_posix_sd(tmpdir)

            assert sd is not None
            assert sd.world_accessible is False

    def test_authenticated_users_for_group_read_without_other(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chmod(tmpdir, 0o750)
            sd = collect_posix_sd(tmpdir)

            assert sd is not None
            assert sd.authenticated_users is True
            assert sd.world_accessible is False

    def test_not_authenticated_users_when_world_accessible(self):
        """authenticated_users is only set when world_accessible is False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chmod(tmpdir, 0o755)
            sd = collect_posix_sd(tmpdir)

            assert sd is not None
            # Per implementation: authenticated_users = group_read AND NOT world_accessible
            assert sd.authenticated_users is False

    def test_permissions_json_has_expected_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sd = collect_posix_sd(tmpdir)

            assert sd is not None
            assert sd.permissions_json is not None
            expected_keys = {
                "uid", "gid", "mode",
                "owner_read", "owner_write", "owner_exec",
                "group_read", "group_write", "group_exec",
                "other_read", "other_write", "other_exec",
            }
            assert set(sd.permissions_json.keys()) == expected_keys

    def test_permissions_json_matches_actual_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chmod(tmpdir, 0o750)
            sd = collect_posix_sd(tmpdir)

            assert sd is not None
            p = sd.permissions_json
            assert p["owner_read"] is True
            assert p["owner_write"] is True
            assert p["owner_exec"] is True
            assert p["group_read"] is True
            assert p["group_write"] is False
            assert p["group_exec"] is True
            assert p["other_read"] is False
            assert p["other_write"] is False
            assert p["other_exec"] is False

    def test_returns_none_for_nonexistent_path(self):
        sd = collect_posix_sd("/nonexistent/path/12345")
        assert sd is None

    def test_two_dirs_same_mode_produce_same_hash(self):
        """Deduplication: identical permissions should hash the same."""
        with tempfile.TemporaryDirectory() as tmpdir:
            a = Path(tmpdir) / "a"
            b = Path(tmpdir) / "b"
            a.mkdir()
            b.mkdir()
            os.chmod(str(a), 0o755)
            os.chmod(str(b), 0o755)

            sd_a = collect_posix_sd(str(a))
            sd_b = collect_posix_sd(str(b))

            assert sd_a is not None and sd_b is not None
            # Same owner (running user), same mode → same hash
            assert sd_a.sd_hash() == sd_b.sd_hash()

    def test_different_modes_produce_different_hash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            a = Path(tmpdir) / "a"
            b = Path(tmpdir) / "b"
            a.mkdir()
            b.mkdir()
            os.chmod(str(a), 0o755)
            os.chmod(str(b), 0o700)

            sd_a = collect_posix_sd(str(a))
            sd_b = collect_posix_sd(str(b))

            assert sd_a is not None and sd_b is not None
            assert sd_a.sd_hash() != sd_b.sd_hash()


class TestCollectBatchSync:

    def test_collects_all_accessible_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            a = Path(tmpdir) / "a"
            b = Path(tmpdir) / "b"
            a.mkdir()
            b.mkdir()

            results = _collect_batch_sync([str(a), str(b)])
            collected_paths = {r[0] for r in results}

            assert str(a) in collected_paths
            assert str(b) in collected_paths
            assert len(results) == 2

    def test_skips_inaccessible_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            a = Path(tmpdir) / "a"
            a.mkdir()

            results = _collect_batch_sync([str(a), "/nonexistent/path/12345"])
            assert len(results) == 1
            assert results[0][0] == str(a)

    def test_empty_input_returns_empty(self):
        results = _collect_batch_sync([])
        assert results == []

    def test_returns_path_sd_pairs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = _collect_batch_sync([tmpdir])
            assert len(results) == 1
            path, sd = results[0]
            assert path == tmpdir
            assert isinstance(sd, SDInfo)


class TestCollectSD:

    def test_returns_sdinfo_for_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sd = collect_sd(tmpdir)
            assert sd is not None
            assert isinstance(sd, SDInfo)

    def test_returns_none_for_nonexistent(self):
        sd = collect_sd("/nonexistent/path/12345")
        assert sd is None
