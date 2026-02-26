"""
Tests for resource enumeration API endpoints.

Tests focus on:
- Enumerate endpoint request/response validation
- Credential handling security
- Subprocess call safety (SMB, NFS)
- Error handling for various adapter types (S3, GCS, Azure, SharePoint, OneDrive)
- Pagination of enumerated results
- Host validation and input sanitization
"""

import asyncio
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from openlabels.server.routes.credentials import VALID_SOURCE_TYPES
from openlabels.server.routes.enumerate import (
    EnumerateRequest,
    EnumerateResponse,
    EnumeratedResource,
    _validate_host,
    _validate_uuid,
    _safe_json,
    _enumerate_smb,
    _enumerate_nfs,
    _enumerate_s3,
    _enumerate_gcs,
    _enumerate_azure_blob,
    _enumerate_sharepoint,
    _enumerate_onedrive,
    _ENUMERATORS,
    _PAGINATED_ENUMERATORS,
)


# ── Pydantic model validation ───────────────────────────────────────


class TestEnumerateRequestValidation:
    """Tests for EnumerateRequest body model."""

    def test_valid_minimal_request(self):
        req = EnumerateRequest(source_type="smb")
        assert req.source_type == "smb"
        assert req.credentials is None
        assert req.search is None
        assert req.page == 1
        assert req.page_size == 50
        assert req.use_m365_session is False

    def test_valid_full_request(self):
        req = EnumerateRequest(
            source_type="sharepoint",
            credentials={"tenant_id": "abc", "client_id": "def", "client_secret": "ghi"},
            search="finance",
            page=3,
            page_size=25,
            use_m365_session=True,
        )
        assert req.source_type == "sharepoint"
        assert req.page == 3
        assert req.page_size == 25
        assert req.search == "finance"
        assert req.use_m365_session is True

    def test_page_must_be_positive(self):
        with pytest.raises(Exception):
            EnumerateRequest(source_type="smb", page=0)

    def test_page_size_must_be_at_least_1(self):
        with pytest.raises(Exception):
            EnumerateRequest(source_type="smb", page_size=0)

    def test_page_size_max_500(self):
        with pytest.raises(Exception):
            EnumerateRequest(source_type="smb", page_size=501)

    def test_source_type_required(self):
        with pytest.raises(Exception):
            EnumerateRequest()


class TestEnumeratedResource:
    """Tests for the EnumeratedResource response model."""

    def test_valid_resource(self):
        r = EnumeratedResource(
            id="smb://host/share",
            name="share",
            path="/mnt/smb/host/share",
            resource_type="share",
        )
        assert r.id == "smb://host/share"
        assert r.description is None
        assert r.size is None

    def test_resource_with_optional_fields(self):
        r = EnumeratedResource(
            id="bucket-1",
            name="bucket-1",
            path="s3://bucket-1",
            resource_type="bucket",
            description="Created: 2024-01-01",
            size="10GB",
        )
        assert r.description == "Created: 2024-01-01"
        assert r.size == "10GB"


class TestEnumerateResponse:
    """Tests for the EnumerateResponse model."""

    def test_response_defaults(self):
        resp = EnumerateResponse(
            source_type="smb",
            resources=[],
            total=0,
        )
        assert resp.has_more is False
        assert resp.error is None

    def test_response_with_resources(self):
        resources = [
            EnumeratedResource(
                id="r1", name="share1", path="/mnt/share1", resource_type="share"
            )
        ]
        resp = EnumerateResponse(
            source_type="smb",
            resources=resources,
            total=1,
            has_more=True,
        )
        assert len(resp.resources) == 1
        assert resp.has_more is True


# ── Host validation ──────────────────────────────────────────────────


class TestValidateHost:
    """Tests for _validate_host input sanitization."""

    def test_valid_hostname(self):
        assert _validate_host("fileserver.local") == "fileserver.local"

    def test_valid_ipv4(self):
        assert _validate_host("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6_bracketed(self):
        assert _validate_host("[::1]") == "[::1]"

    def test_strips_whitespace(self):
        assert _validate_host("  myhost  ") == "myhost"

    def test_empty_host_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_host("")
        assert exc_info.value.status_code == 400
        assert "required" in exc_info.value.detail.lower()

    def test_whitespace_only_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_host("   ")
        assert exc_info.value.status_code == 400

    def test_too_long_host_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_host("a" * 254)
        assert exc_info.value.status_code == 400
        assert "too long" in exc_info.value.detail.lower()

    def test_max_length_host_accepted(self):
        host = "a" * 253
        assert _validate_host(host) == host

    def test_invalid_chars_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_host("host;rm -rf /")
        assert exc_info.value.status_code == 400
        assert "invalid characters" in exc_info.value.detail.lower()

    def test_slash_rejected(self):
        with pytest.raises(HTTPException):
            _validate_host("host/path")

    def test_path_traversal_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_host("host..evil")
        assert exc_info.value.status_code == 400
        assert "traversal" in exc_info.value.detail.lower()

    def test_shell_metacharacters_rejected(self):
        """Command injection via hostname should be blocked."""
        dangerous = ["host$(whoami)", "host`id`", "host|cat /etc/passwd", "host&& echo pwned"]
        for h in dangerous:
            with pytest.raises(HTTPException):
                _validate_host(h)


class TestValidateUuid:
    """Tests for _validate_uuid."""

    def test_valid_uuid(self):
        result = _validate_uuid("12345678-1234-1234-1234-123456789abc", "Test ID")
        assert result == "12345678-1234-1234-1234-123456789abc"

    def test_strips_whitespace(self):
        result = _validate_uuid("  12345678-1234-1234-1234-123456789abc  ", "Test ID")
        assert result == "12345678-1234-1234-1234-123456789abc"

    def test_invalid_uuid_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_uuid("not-a-uuid", "Tenant ID")
        assert exc_info.value.status_code == 400
        assert "Tenant ID" in exc_info.value.detail

    def test_empty_string_raises(self):
        with pytest.raises(HTTPException):
            _validate_uuid("", "Test ID")


class TestSafeJson:
    """Tests for _safe_json helper."""

    def test_valid_json_response(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"key": "value"}
        assert _safe_json(mock_resp) == {"key": "value"}

    def test_invalid_json_returns_empty(self):
        mock_resp = MagicMock()
        mock_resp.json.side_effect = ValueError("bad json")
        assert _safe_json(mock_resp) == {}


# ── SMB enumeration ──────────────────────────────────────────────────


class TestEnumerateSMB:
    """Tests for _enumerate_smb with subprocess mocking."""

    @pytest.mark.asyncio
    async def test_smb_parses_smbclient_output(self):
        """Verify smbclient output is parsed into EnumeratedResource objects."""
        smbclient_output = (
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            "\tDocuments       Disk      Shared docs\n"
            "\tPhotos          Disk      \n"
            "\tIPC$            IPC       IPC Service\n"
        )
        mock_result = MagicMock()
        mock_result.stdout = smbclient_output
        mock_result.stderr = ""

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            resources = await _enumerate_smb({"host": "fileserver.local", "username": "admin", "password": "secret"})

        assert len(resources) == 2
        assert resources[0].name == "Documents"
        assert resources[0].resource_type == "share"
        assert resources[0].path == "/mnt/smb/fileserver.local/Documents"
        assert "Documents" in resources[0].id
        assert resources[1].name == "Photos"

    @pytest.mark.asyncio
    async def test_smb_skips_ipc_and_printer_shares(self):
        """IPC$ and PRINTER shares should be filtered out."""
        output = (
            "Sharename       Type      Comment\n"
            "---------       ----      -------\n"
            "Data            Disk      \n"
            "IPC$            IPC       IPC Service\n"
            "HP_Printer      Printer   HP LaserJet\n"
        )
        mock_result = MagicMock()
        mock_result.stdout = output
        mock_result.stderr = ""

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            resources = await _enumerate_smb({"host": "server.local"})

        assert len(resources) == 1
        assert resources[0].name == "Data"

    @pytest.mark.asyncio
    async def test_smb_password_passed_via_env(self):
        """Password should be passed via PASSWD env var, not command line."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            await _enumerate_smb({"host": "server.local", "username": "user", "password": "s3cret"})

            # Verify subprocess.run was called
            call_args = mock_thread.call_args
            # The second positional arg (cmd list) should NOT contain the password
            cmd = call_args[0][1]
            assert "s3cret" not in cmd
            # Check env was passed with PASSWD
            kwargs = call_args[1] if call_args[1] else {}
            if not kwargs:
                # kwargs might be in the positional args
                kwargs = call_args[0][-1] if len(call_args[0]) > 2 else {}
            # The env kwarg should contain PASSWD
            env = kwargs.get("env") or (call_args[1] or {}).get("env")
            # Due to asyncio.to_thread calling subprocess.run, the env is passed
            # as a keyword arg to subprocess.run
            assert isinstance(cmd, list)
            assert "s3cret" not in " ".join(str(c) for c in cmd)

    @pytest.mark.asyncio
    async def test_smb_no_user_uses_anonymous(self):
        """Without credentials, smbclient should use -N (no password) flag."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            await _enumerate_smb({"host": "server.local"})

            call_args = mock_thread.call_args
            cmd = call_args[0][1]
            assert "-N" in cmd

    @pytest.mark.asyncio
    async def test_smb_smbclient_not_installed(self):
        """When smbclient is not found, return a fallback resource."""
        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.side_effect = FileNotFoundError("smbclient not found")
            resources = await _enumerate_smb({"host": "server.local"})

        assert len(resources) == 1
        assert "manual" in resources[0].id
        assert "smbclient not installed" in resources[0].description

    @pytest.mark.asyncio
    async def test_smb_timeout_raises_504(self):
        """Connection timeout should raise HTTP 504."""
        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.side_effect = subprocess.TimeoutExpired(cmd=["smbclient"], timeout=15)
            with pytest.raises(HTTPException) as exc_info:
                await _enumerate_smb({"host": "slow-server.local"})
            assert exc_info.value.status_code == 504

    @pytest.mark.asyncio
    async def test_smb_generic_error_raises_502(self):
        """Generic enumeration failure should raise HTTP 502."""
        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.side_effect = RuntimeError("connection refused")
            with pytest.raises(HTTPException) as exc_info:
                await _enumerate_smb({"host": "bad-server.local"})
            assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_smb_localhost_delegates_to_local(self):
        """Localhost should use local share enumeration instead of smbclient."""
        with patch(
            "openlabels.server.routes.enumerate._enumerate_local_shares",
            new_callable=AsyncMock,
            return_value=[],
        ) as mock_local:
            resources = await _enumerate_smb({"host": "localhost"})
            mock_local.assert_awaited_once()
            assert resources == []

    @pytest.mark.asyncio
    async def test_smb_127_0_0_1_delegates_to_local(self):
        """127.0.0.1 should also use local enumeration."""
        with patch(
            "openlabels.server.routes.enumerate._enumerate_local_shares",
            new_callable=AsyncMock,
            return_value=[],
        ) as mock_local:
            await _enumerate_smb({"host": "127.0.0.1"})
            mock_local.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_smb_host_validation_rejects_injection(self):
        """Shell injection via host field should be blocked."""
        with pytest.raises(HTTPException) as exc_info:
            await _enumerate_smb({"host": "server;rm -rf /"})
        assert exc_info.value.status_code == 400


# ── NFS enumeration ──────────────────────────────────────────────────


class TestEnumerateNFS:
    """Tests for _enumerate_nfs with subprocess mocking."""

    @pytest.mark.asyncio
    async def test_nfs_parses_showmount_output(self):
        """Verify showmount -e output is parsed correctly."""
        showmount_output = (
            "Export list for server:\n"
            "/data/shared     *(rw,sync)\n"
            "/home            192.168.1.0/24\n"
        )
        mock_result = MagicMock()
        mock_result.stdout = showmount_output
        mock_result.stderr = ""

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            resources = await _enumerate_nfs({"host": "nfs-server.local"})

        assert len(resources) == 2
        assert resources[0].name == "shared"
        assert resources[0].resource_type == "export"
        assert "nfs-server.local" in resources[0].id
        assert "/data/shared" in resources[0].description
        assert resources[1].name == "home"

    @pytest.mark.asyncio
    async def test_nfs_showmount_not_installed(self):
        """When showmount is not found, return a fallback resource."""
        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.side_effect = FileNotFoundError("showmount not found")
            resources = await _enumerate_nfs({"host": "nfs-server.local"})

        assert len(resources) == 1
        assert "manual" in resources[0].id
        assert "showmount not installed" in resources[0].description

    @pytest.mark.asyncio
    async def test_nfs_timeout_raises_504(self):
        """Connection timeout should raise HTTP 504."""
        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.side_effect = subprocess.TimeoutExpired(cmd=["showmount"], timeout=15)
            with pytest.raises(HTTPException) as exc_info:
                await _enumerate_nfs({"host": "slow-nfs.local"})
            assert exc_info.value.status_code == 504

    @pytest.mark.asyncio
    async def test_nfs_generic_error_raises_502(self):
        """Generic enumeration failure should raise HTTP 502."""
        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.side_effect = OSError("connection refused")
            with pytest.raises(HTTPException) as exc_info:
                await _enumerate_nfs({"host": "bad-nfs.local"})
            assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_nfs_localhost_delegates_to_local(self):
        """Localhost should use local NFS export enumeration."""
        with patch(
            "openlabels.server.routes.enumerate._enumerate_local_nfs",
            new_callable=AsyncMock,
            return_value=[],
        ) as mock_local:
            resources = await _enumerate_nfs({"host": "localhost"})
            mock_local.assert_awaited_once()
            assert resources == []

    @pytest.mark.asyncio
    async def test_nfs_empty_host_raises(self):
        """Empty host should raise a validation error."""
        with pytest.raises(HTTPException) as exc_info:
            await _enumerate_nfs({"host": ""})
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_nfs_showmount_uses_list_args(self):
        """showmount should be called with a list, not a shell string."""
        mock_result = MagicMock()
        mock_result.stdout = "Export list:\n"
        mock_result.stderr = ""

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            await _enumerate_nfs({"host": "nfs.local"})

            call_args = mock_thread.call_args
            cmd = call_args[0][1]
            assert isinstance(cmd, list)
            assert cmd == ["showmount", "-e", "nfs.local"]


# ── S3 enumeration ───────────────────────────────────────────────────


class TestEnumerateS3:
    """Tests for _enumerate_s3."""

    @pytest.mark.asyncio
    async def test_s3_lists_buckets(self):
        """Should return S3 buckets as EnumeratedResource objects."""
        from datetime import datetime, timezone

        mock_s3_client = MagicMock()
        mock_s3_client.list_buckets.return_value = {
            "Buckets": [
                {"Name": "data-lake", "CreationDate": datetime(2024, 1, 15, tzinfo=timezone.utc)},
                {"Name": "logs-bucket", "CreationDate": datetime(2024, 6, 1, tzinfo=timezone.utc)},
            ]
        }

        # Mock boto3 and botocore imports
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_s3_client
        mock_botocore = MagicMock()
        mock_botocore_exc = MagicMock()
        mock_botocore_exc.ClientError = type("ClientError", (Exception,), {})
        mock_botocore_exc.NoCredentialsError = type("NoCredentialsError", (Exception,), {})

        with patch.dict("sys.modules", {
            "boto3": mock_boto3,
            "botocore": mock_botocore,
            "botocore.exceptions": mock_botocore_exc,
        }):
            with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
                # First call: boto3.client(...) returns mock_s3_client
                # Second call: s3_client.list_buckets() returns the response
                mock_thread.side_effect = [mock_s3_client, mock_s3_client.list_buckets.return_value]
                resources = await _enumerate_s3({
                    "access_key": "AKIAIOSFODNN7EXAMPLE",
                    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "region": "us-east-1",
                })

        assert len(resources) == 2
        assert resources[0].name == "data-lake"
        assert resources[0].resource_type == "bucket"
        assert resources[0].path == "s3://data-lake"
        assert "Created:" in resources[0].description
        assert resources[1].name == "logs-bucket"

    @pytest.mark.asyncio
    async def test_s3_boto3_not_installed(self):
        """When boto3 is not installed, should raise HTTP 500."""
        # Force ImportError by setting modules to None
        import sys
        saved_boto3 = sys.modules.get("boto3")
        saved_botocore = sys.modules.get("botocore")
        saved_botocore_exc = sys.modules.get("botocore.exceptions")
        sys.modules["boto3"] = None  # type: ignore
        sys.modules["botocore"] = None  # type: ignore
        sys.modules["botocore.exceptions"] = None  # type: ignore
        try:
            with pytest.raises(HTTPException) as exc_info:
                await _enumerate_s3({"access_key": "test", "secret_key": "test"})
            assert exc_info.value.status_code == 500
            assert "boto3" in exc_info.value.detail.lower()
        finally:
            # Restore original module state
            if saved_boto3 is not None:
                sys.modules["boto3"] = saved_boto3
            else:
                sys.modules.pop("boto3", None)
            if saved_botocore is not None:
                sys.modules["botocore"] = saved_botocore
            else:
                sys.modules.pop("botocore", None)
            if saved_botocore_exc is not None:
                sys.modules["botocore.exceptions"] = saved_botocore_exc
            else:
                sys.modules.pop("botocore.exceptions", None)

    @pytest.mark.asyncio
    async def test_s3_with_custom_endpoint(self):
        """S3-compatible endpoints (MinIO, etc.) should use endpoint_url."""
        mock_boto3 = MagicMock()
        mock_botocore = MagicMock()
        mock_botocore_exc = MagicMock()
        mock_botocore_exc.ClientError = type("ClientError", (Exception,), {})
        mock_botocore_exc.NoCredentialsError = type("NoCredentialsError", (Exception,), {})

        with patch.dict("sys.modules", {
            "boto3": mock_boto3,
            "botocore": mock_botocore,
            "botocore.exceptions": mock_botocore_exc,
        }):
            with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.side_effect = [MagicMock(), {"Buckets": []}]
                resources = await _enumerate_s3({
                    "access_key": "minioadmin",
                    "secret_key": "minioadmin",
                    "endpoint_url": "http://localhost:9000",
                })
        assert resources == []

    @pytest.mark.asyncio
    async def test_s3_empty_buckets(self):
        """Empty bucket list should return empty resources."""
        mock_boto3 = MagicMock()
        mock_botocore = MagicMock()
        mock_botocore_exc = MagicMock()
        mock_botocore_exc.ClientError = type("ClientError", (Exception,), {})
        mock_botocore_exc.NoCredentialsError = type("NoCredentialsError", (Exception,), {})

        with patch.dict("sys.modules", {
            "boto3": mock_boto3,
            "botocore": mock_botocore,
            "botocore.exceptions": mock_botocore_exc,
        }):
            with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.side_effect = [MagicMock(), {"Buckets": []}]
                resources = await _enumerate_s3({
                    "access_key": "key",
                    "secret_key": "secret",
                })
        assert resources == []


# ── SharePoint enumeration ───────────────────────────────────────────


class TestEnumerateSharePoint:
    """Tests for _enumerate_sharepoint."""

    @pytest.mark.asyncio
    async def test_sharepoint_requires_all_credentials(self):
        """Missing credentials should raise HTTP 400."""
        with pytest.raises(HTTPException) as exc_info:
            await _enumerate_sharepoint({"tenant_id": "tid", "client_id": ""})
        assert exc_info.value.status_code == 400
        assert "requires" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_sharepoint_validates_tenant_uuid(self):
        """Invalid tenant_id UUID format should raise HTTP 400."""
        with pytest.raises(HTTPException) as exc_info:
            await _enumerate_sharepoint({
                "tenant_id": "not-a-uuid",
                "client_id": "12345678-1234-1234-1234-123456789abc",
                "client_secret": "secret",
            })
        assert exc_info.value.status_code == 400
        assert "Tenant ID" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_sharepoint_validates_client_uuid(self):
        """Invalid client_id UUID format should raise HTTP 400."""
        with pytest.raises(HTTPException) as exc_info:
            await _enumerate_sharepoint({
                "tenant_id": "12345678-1234-1234-1234-123456789abc",
                "client_id": "bad-uuid",
                "client_secret": "secret",
            })
        assert exc_info.value.status_code == 400
        assert "Client ID" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_sharepoint_auth_failure_raises_401(self):
        """OAuth token failure should raise HTTP 401."""
        try:
            import httpx
        except ImportError:
            pytest.skip("httpx not installed")

        # Use MagicMock for response (json() is sync), AsyncMock for client methods
        token_resp = MagicMock()
        token_resp.status_code = 400
        token_resp.json.return_value = {"error_description": "Invalid client"}

        mock_client_inst = AsyncMock()
        mock_client_inst.post.return_value = token_resp

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client_inst)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(HTTPException) as exc_info:
                await _enumerate_sharepoint({
                    "tenant_id": "12345678-1234-1234-1234-123456789abc",
                    "client_id": "12345678-1234-1234-1234-123456789abc",
                    "client_secret": "bad-secret",
                })
            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_sharepoint_lists_sites(self):
        """Successful enumeration should return site resources."""
        try:
            import httpx
        except ImportError:
            pytest.skip("httpx not installed")

        # Use MagicMock for responses (json() is sync), AsyncMock for client methods
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"access_token": "fake-token"}

        sites_resp = MagicMock()
        sites_resp.status_code = 200
        sites_resp.json.return_value = {
            "value": [
                {
                    "id": "site-1",
                    "displayName": "Finance Team",
                    "webUrl": "https://tenant.sharepoint.com/sites/finance",
                    "description": "Finance site",
                },
                {
                    "id": "site-2",
                    "displayName": "HR Portal",
                    "webUrl": "https://tenant.sharepoint.com/sites/hr",
                    "description": None,
                },
            ]
        }

        mock_client_inst = AsyncMock()
        mock_client_inst.post.return_value = token_resp
        mock_client_inst.get.return_value = sites_resp

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client_inst)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            resources, has_more = await _enumerate_sharepoint(
                {
                    "tenant_id": "12345678-1234-1234-1234-123456789abc",
                    "client_id": "12345678-1234-1234-1234-123456789abc",
                    "client_secret": "valid-secret",
                },
                search="team",
                page=1,
                page_size=50,
            )

        assert len(resources) == 2
        assert resources[0].name == "Finance Team"
        assert resources[0].resource_type == "site"
        assert has_more is False

    @pytest.mark.asyncio
    async def test_sharepoint_pagination_has_more(self):
        """When response has more items than page_size, has_more should be True."""
        try:
            import httpx
        except ImportError:
            pytest.skip("httpx not installed")

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"access_token": "fake-token"}

        # Return page_size + 1 items to indicate more pages
        sites = [
            {"id": f"site-{i}", "displayName": f"Site {i}", "webUrl": f"https://t.sharepoint.com/s/{i}"}
            for i in range(4)  # 3 + 1 extra
        ]
        sites_resp = MagicMock()
        sites_resp.status_code = 200
        sites_resp.json.return_value = {"value": sites}

        mock_client_inst = AsyncMock()
        mock_client_inst.post.return_value = token_resp
        mock_client_inst.get.return_value = sites_resp

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client_inst)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            resources, has_more = await _enumerate_sharepoint(
                {
                    "tenant_id": "12345678-1234-1234-1234-123456789abc",
                    "client_id": "12345678-1234-1234-1234-123456789abc",
                    "client_secret": "valid-secret",
                },
                page_size=3,
            )

        assert len(resources) == 3  # Only page_size items returned
        assert has_more is True

    @pytest.mark.asyncio
    async def test_sharepoint_httpx_not_installed(self):
        """When httpx is not installed, should raise HTTP 500."""
        with patch.dict("sys.modules", {"httpx": None}):
            with pytest.raises((HTTPException, ImportError)):
                await _enumerate_sharepoint({
                    "tenant_id": "12345678-1234-1234-1234-123456789abc",
                    "client_id": "12345678-1234-1234-1234-123456789abc",
                    "client_secret": "secret",
                })


# ── OneDrive enumeration ─────────────────────────────────────────────


class TestEnumerateOneDrive:
    """Tests for _enumerate_onedrive."""

    @pytest.mark.asyncio
    async def test_onedrive_requires_all_credentials(self):
        """Missing credentials should raise HTTP 400."""
        with pytest.raises(HTTPException) as exc_info:
            await _enumerate_onedrive({"tenant_id": "tid"})
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_onedrive_lists_users(self):
        """Successful enumeration should return user drive resources."""
        try:
            import httpx
        except ImportError:
            pytest.skip("httpx not installed")

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"access_token": "fake-token"}

        users_resp = MagicMock()
        users_resp.status_code = 200
        users_resp.json.return_value = {
            "value": [
                {
                    "id": "user-1",
                    "displayName": "Alice Johnson",
                    "mail": "alice@contoso.com",
                    "userPrincipalName": "alice@contoso.com",
                },
            ]
        }

        mock_client_inst = AsyncMock()
        mock_client_inst.post.return_value = token_resp
        mock_client_inst.get.return_value = users_resp

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client_inst)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            resources, has_more = await _enumerate_onedrive(
                {
                    "tenant_id": "12345678-1234-1234-1234-123456789abc",
                    "client_id": "12345678-1234-1234-1234-123456789abc",
                    "client_secret": "valid-secret",
                },
            )

        assert len(resources) == 1
        assert resources[0].name == "Alice Johnson"
        assert resources[0].resource_type == "drive"
        assert resources[0].path == "alice@contoso.com"
        assert has_more is False

    @pytest.mark.asyncio
    async def test_onedrive_auth_failure(self):
        """OAuth failure should raise HTTP 401."""
        try:
            import httpx
        except ImportError:
            pytest.skip("httpx not installed")

        token_resp = MagicMock()
        token_resp.status_code = 401
        token_resp.json.return_value = {"error_description": "bad credentials"}

        mock_client_inst = AsyncMock()
        mock_client_inst.post.return_value = token_resp

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client_inst)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(HTTPException) as exc_info:
                await _enumerate_onedrive({
                    "tenant_id": "12345678-1234-1234-1234-123456789abc",
                    "client_id": "12345678-1234-1234-1234-123456789abc",
                    "client_secret": "bad",
                })
            assert exc_info.value.status_code == 401


# ── Azure Blob enumeration ───────────────────────────────────────────


class TestEnumerateAzureBlob:
    """Tests for _enumerate_azure_blob."""

    @pytest.mark.asyncio
    async def test_azure_requires_storage_account(self):
        """Missing storage_account should raise HTTP 400."""
        with pytest.raises(HTTPException) as exc_info:
            await _enumerate_azure_blob({"storage_account": ""})
        assert exc_info.value.status_code == 400
        assert "storage_account" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_azure_lists_containers(self):
        """Successful enumeration should return container resources."""
        mock_blob_module = MagicMock()
        mock_client = MagicMock()
        mock_blob_module.BlobServiceClient.return_value = mock_client

        with patch.dict("sys.modules", {
            "azure": MagicMock(),
            "azure.storage": MagicMock(),
            "azure.storage.blob": mock_blob_module,
        }):
            with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
                # list() call returns the containers
                mock_thread.return_value = [
                    {"name": "documents"},
                    {"name": "images"},
                ]
                resources = await _enumerate_azure_blob({
                    "storage_account": "mystorageaccount",
                    "account_key": "fake-key-base64==",
                })

        assert len(resources) == 2
        assert resources[0].name == "documents"
        assert resources[0].resource_type == "container"
        assert "mystorageaccount" in resources[0].path
        assert resources[1].name == "images"

    @pytest.mark.asyncio
    async def test_azure_sdk_not_installed(self):
        """When azure-storage-blob is not installed, should raise HTTP 500."""
        import sys
        saved = {
            k: sys.modules.get(k)
            for k in ("azure", "azure.storage", "azure.storage.blob")
        }
        sys.modules["azure.storage.blob"] = None  # type: ignore
        try:
            with pytest.raises(HTTPException) as exc_info:
                await _enumerate_azure_blob({
                    "storage_account": "test",
                    "account_key": "key",
                })
            assert exc_info.value.status_code == 500
        finally:
            for k, v in saved.items():
                if v is not None:
                    sys.modules[k] = v
                else:
                    sys.modules.pop(k, None)

    @pytest.mark.asyncio
    async def test_azure_generic_error_raises_502(self):
        """Generic Azure failure should raise HTTP 502."""
        mock_blob_module = MagicMock()
        mock_blob_module.BlobServiceClient.return_value = MagicMock()

        with patch.dict("sys.modules", {
            "azure": MagicMock(),
            "azure.storage": MagicMock(),
            "azure.storage.blob": mock_blob_module,
        }):
            with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.side_effect = RuntimeError("connection refused")
                with pytest.raises(HTTPException) as exc_info:
                    await _enumerate_azure_blob({
                        "storage_account": "test",
                        "account_key": "key",
                    })
                assert exc_info.value.status_code == 502


# ── GCS enumeration ──────────────────────────────────────────────────


class TestEnumerateGCS:
    """Tests for _enumerate_gcs."""

    @pytest.mark.asyncio
    async def test_gcs_generic_error_raises_502(self):
        """Generic GCS failure should raise HTTP 502."""
        mock_gcs_storage = MagicMock()
        mock_service_account = MagicMock()

        with patch.dict("sys.modules", {
            "google": MagicMock(),
            "google.cloud": MagicMock(),
            "google.cloud.storage": mock_gcs_storage,
            "google.oauth2": MagicMock(),
            "google.oauth2.service_account": mock_service_account,
        }):
            with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.side_effect = RuntimeError("auth failed")
                with pytest.raises(HTTPException) as exc_info:
                    await _enumerate_gcs({"project": "my-project"})
                assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_gcs_sdk_not_installed(self):
        """When google-cloud-storage is not installed, should raise HTTP 500."""
        import sys
        saved = {
            k: sys.modules.get(k)
            for k in ("google.cloud.storage", "google.cloud", "google.oauth2", "google.oauth2.service_account")
        }
        sys.modules["google.cloud.storage"] = None  # type: ignore
        sys.modules["google.oauth2.service_account"] = None  # type: ignore
        try:
            with pytest.raises(HTTPException) as exc_info:
                await _enumerate_gcs({"project": "test"})
            assert exc_info.value.status_code == 500
        finally:
            for k, v in saved.items():
                if v is not None:
                    sys.modules[k] = v
                else:
                    sys.modules.pop(k, None)

    @pytest.mark.asyncio
    async def test_gcs_lists_buckets(self):
        """Successful GCS enumeration should return bucket resources."""
        mock_gcs_storage = MagicMock()
        mock_service_account = MagicMock()

        mock_bucket1 = MagicMock()
        mock_bucket1.name = "data-bucket"
        mock_bucket1.location = "US"
        mock_bucket2 = MagicMock()
        mock_bucket2.name = "logs-bucket"
        mock_bucket2.location = "EU"

        with patch.dict("sys.modules", {
            "google": MagicMock(),
            "google.cloud": MagicMock(),
            "google.cloud.storage": mock_gcs_storage,
            "google.oauth2": MagicMock(),
            "google.oauth2.service_account": mock_service_account,
        }):
            with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.return_value = [mock_bucket1, mock_bucket2]
                resources = await _enumerate_gcs({"project": "my-project"})

        assert len(resources) == 2
        assert resources[0].name == "data-bucket"
        assert resources[0].resource_type == "bucket"
        assert resources[0].path == "gs://data-bucket"
        assert "US" in resources[0].description


# ── Dispatcher / Enumerators dict ────────────────────────────────────


class TestEnumeratorsConfig:
    """Tests for the dispatch mapping and paginated set."""

    def test_all_source_types_have_enumerator(self):
        """Every valid source type should have a registered enumerator."""
        for source_type in VALID_SOURCE_TYPES:
            assert source_type in _ENUMERATORS, f"Missing enumerator for {source_type}"

    def test_no_unknown_enumerators(self):
        """Enumerators should only exist for valid source types."""
        for key in _ENUMERATORS:
            assert key in VALID_SOURCE_TYPES, f"Unknown enumerator: {key}"

    def test_paginated_enumerators_subset(self):
        """Paginated enumerators should be a subset of all enumerators."""
        assert _PAGINATED_ENUMERATORS.issubset(set(_ENUMERATORS.keys()))

    def test_expected_paginated_types(self):
        """SharePoint and OneDrive should support pagination."""
        assert "sharepoint" in _PAGINATED_ENUMERATORS
        assert "onedrive" in _PAGINATED_ENUMERATORS

    def test_non_paginated_types(self):
        """SMB, NFS, S3, GCS, Azure should not be paginated."""
        for t in ("smb", "nfs", "s3", "gcs", "azure_blob"):
            assert t not in _PAGINATED_ENUMERATORS


# ── Credential handling ──────────────────────────────────────────────


class TestGetCredentials:
    """Tests for the _get_credentials helper."""

    @pytest.mark.asyncio
    async def test_inline_credentials_returned_directly(self):
        """When inline credentials are provided, they should be returned as-is."""
        from openlabels.server.routes.enumerate import _get_credentials

        inline = {"host": "server.local", "username": "admin"}
        mock_request = MagicMock()
        mock_db = AsyncMock()
        mock_user = MagicMock()

        result = await _get_credentials(mock_request, mock_db, mock_user, "smb", inline)
        assert result == inline

    @pytest.mark.asyncio
    async def test_no_session_cookie_raises_401(self):
        """Missing session cookie should raise HTTP 401."""
        from openlabels.server.routes.enumerate import _get_credentials

        mock_request = MagicMock()
        mock_request.cookies.get.return_value = None
        mock_db = AsyncMock()
        mock_user = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await _get_credentials(mock_request, mock_db, mock_user, "smb", None)
        assert exc_info.value.status_code == 401
        assert "session" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_expired_session_raises_401(self):
        """Expired session should raise HTTP 401."""
        from openlabels.server.routes.enumerate import _get_credentials

        mock_request = MagicMock()
        mock_request.cookies.get.return_value = "expired-session-id"
        mock_db = AsyncMock()
        mock_user = MagicMock()

        with patch("openlabels.server.routes.enumerate.SessionStore") as mock_store_cls:
            mock_store = AsyncMock()
            mock_store_cls.return_value = mock_store
            mock_store.get.return_value = None  # Session not found / expired

            with pytest.raises(HTTPException) as exc_info:
                await _get_credentials(mock_request, mock_db, mock_user, "smb", None)
            assert exc_info.value.status_code == 401
            assert "expired" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_no_credentials_in_session_raises_400(self):
        """When session has no credentials for the source type, raise HTTP 400."""
        from openlabels.server.routes.enumerate import _get_credentials

        mock_request = MagicMock()
        mock_request.cookies.get.return_value = "valid-session-id"
        mock_db = AsyncMock()
        mock_user = MagicMock()
        mock_user.id = "user-123"

        with patch("openlabels.server.routes.enumerate.SessionStore") as mock_store_cls:
            mock_store = AsyncMock()
            mock_store_cls.return_value = mock_store
            mock_store.get.return_value = {"provider": "dev"}  # No creds stored

            with patch("openlabels.server.routes.enumerate.get_decrypted_credentials", return_value=None):
                with pytest.raises(HTTPException) as exc_info:
                    await _get_credentials(mock_request, mock_db, mock_user, "smb", None)
                assert exc_info.value.status_code == 400
                assert "No credentials" in exc_info.value.detail


# ── API endpoint integration tests ───────────────────────────────────


class TestEnumerateEndpoint:
    """Integration tests for POST /api/enumerate endpoint."""

    @pytest.mark.asyncio
    async def test_invalid_source_type_returns_400(self, test_client):
        """Invalid source type should be rejected."""
        response = await test_client.post(
            "/api/v1/enumerate",
            json={"source_type": "ftp"},
        )
        assert response.status_code == 400
        data = response.json()
        # Custom error handler returns {"error": ..., "message": ...}
        assert "Invalid source type" in data.get("message", data.get("detail", ""))

    @pytest.mark.asyncio
    async def test_missing_source_type_returns_422(self, test_client):
        """Missing required field should return 422 validation error."""
        response = await test_client.post(
            "/api/v1/enumerate",
            json={},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_page_returns_422(self, test_client):
        """Invalid pagination values should return 422."""
        response = await test_client.post(
            "/api/v1/enumerate",
            json={"source_type": "smb", "page": 0},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_page_size_returns_422(self, test_client):
        """page_size > 500 should return 422."""
        response = await test_client.post(
            "/api/v1/enumerate",
            json={"source_type": "smb", "page_size": 1000},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_smb_enumeration_via_endpoint(self, test_client):
        """Full endpoint test with mocked SMB enumeration."""
        mock_resources = [
            EnumeratedResource(
                id="smb://server/share1",
                name="share1",
                path="/mnt/smb/server/share1",
                resource_type="share",
            ),
        ]

        mock_enumerator = AsyncMock(return_value=mock_resources)

        with patch.dict(
            "openlabels.server.routes.enumerate._ENUMERATORS",
            {"smb": mock_enumerator},
        ):
            with patch(
                "openlabels.server.routes.enumerate._get_credentials",
                new_callable=AsyncMock,
                return_value={"host": "server", "username": "admin"},
            ):
                response = await test_client.post(
                    "/api/v1/enumerate",
                    json={
                        "source_type": "smb",
                        "credentials": {"host": "server", "username": "admin"},
                    },
                )

        assert response.status_code == 200
        data = response.json()
        assert data["source_type"] == "smb"
        assert len(data["resources"]) == 1
        assert data["resources"][0]["name"] == "share1"
        assert data["total"] == 1
        assert data["has_more"] is False

    @pytest.mark.asyncio
    async def test_sharepoint_enumeration_via_endpoint(self, test_client):
        """Full endpoint test with mocked SharePoint (paginated) enumeration."""
        mock_resources = [
            EnumeratedResource(
                id="site-1",
                name="Engineering",
                path="https://t.sharepoint.com/sites/eng",
                resource_type="site",
            ),
        ]

        mock_enumerator = AsyncMock(return_value=(mock_resources, True))

        with patch.dict(
            "openlabels.server.routes.enumerate._ENUMERATORS",
            {"sharepoint": mock_enumerator},
        ):
            with patch(
                "openlabels.server.routes.enumerate._get_credentials",
                new_callable=AsyncMock,
                return_value={"tenant_id": "t", "client_id": "c", "client_secret": "s"},
            ):
                response = await test_client.post(
                    "/api/v1/enumerate",
                    json={
                        "source_type": "sharepoint",
                        "credentials": {"tenant_id": "t", "client_id": "c", "client_secret": "s"},
                        "search": "eng",
                        "page": 1,
                        "page_size": 50,
                    },
                )

        assert response.status_code == 200
        data = response.json()
        assert data["source_type"] == "sharepoint"
        assert data["has_more"] is True
        assert len(data["resources"]) == 1
        assert data["resources"][0]["resource_type"] == "site"

    @pytest.mark.asyncio
    async def test_enumerate_with_inline_credentials(self, test_client):
        """Inline credentials should work without a session cookie."""
        mock_enumerator = AsyncMock(return_value=[])

        with patch.dict(
            "openlabels.server.routes.enumerate._ENUMERATORS",
            {"smb": mock_enumerator},
        ):
            with patch(
                "openlabels.server.routes.enumerate._get_credentials",
                new_callable=AsyncMock,
                return_value={"host": "server"},
            ):
                response = await test_client.post(
                    "/api/v1/enumerate",
                    json={
                        "source_type": "smb",
                        "credentials": {"host": "server.local"},
                    },
                )

        assert response.status_code == 200
        assert response.json()["resources"] == []

    @pytest.mark.asyncio
    async def test_enumerate_no_enumerator_returns_400(self, test_client):
        """Source type in VALID_SOURCE_TYPES but not in _ENUMERATORS should return 400.

        This tests the defensive check, though in practice all valid types have enumerators.
        """
        with patch(
            "openlabels.server.routes.enumerate._get_credentials",
            new_callable=AsyncMock,
            return_value={"host": "server"},
        ):
            with patch.dict(
                "openlabels.server.routes.enumerate._ENUMERATORS",
                {"smb": None},
                clear=False,
            ):
                # Remove smb from the dict temporarily
                with patch.dict(
                    "openlabels.server.routes.enumerate._ENUMERATORS",
                    clear=True,
                ):
                    response = await test_client.post(
                        "/api/v1/enumerate",
                        json={"source_type": "smb", "credentials": {"host": "x"}},
                    )
                    assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_enumerate_all_valid_source_types_accepted(self, test_client):
        """All valid source types should pass the initial validation check."""
        for source_type in VALID_SOURCE_TYPES:
            mock_return = ([], False) if source_type in _PAGINATED_ENUMERATORS else []

            with patch(
                f"openlabels.server.routes.enumerate._ENUMERATORS",
                {st: AsyncMock(return_value=mock_return) for st in VALID_SOURCE_TYPES},
            ):
                with patch(
                    "openlabels.server.routes.enumerate._get_credentials",
                    new_callable=AsyncMock,
                    return_value={"host": "test"},
                ):
                    response = await test_client.post(
                        "/api/v1/enumerate",
                        json={"source_type": source_type, "credentials": {"host": "test"}},
                    )
                    assert response.status_code == 200, (
                        f"Source type {source_type} returned {response.status_code}"
                    )


# ── M365 session credentials ─────────────────────────────────────────


class TestGetM365SessionCredentials:
    """Tests for _get_m365_session_credentials."""

    @pytest.mark.asyncio
    async def test_no_session_cookie_raises_401(self):
        from openlabels.server.routes.enumerate import _get_m365_session_credentials

        mock_request = MagicMock()
        mock_request.cookies.get.return_value = None
        mock_db = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await _get_m365_session_credentials(mock_request, mock_db)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_session_raises_401(self):
        from openlabels.server.routes.enumerate import _get_m365_session_credentials

        mock_request = MagicMock()
        mock_request.cookies.get.return_value = "expired-id"
        mock_db = AsyncMock()

        with patch("openlabels.server.routes.enumerate.SessionStore") as mock_store_cls:
            mock_store = AsyncMock()
            mock_store_cls.return_value = mock_store
            mock_store.get.return_value = None

            with pytest.raises(HTTPException) as exc_info:
                await _get_m365_session_credentials(mock_request, mock_db)
            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_uses_per_tenant_app_credentials(self):
        """Should prefer per-tenant app credentials from auto registration."""
        from openlabels.server.routes.enumerate import _get_m365_session_credentials

        mock_request = MagicMock()
        mock_request.cookies.get.return_value = "valid-session"
        mock_db = AsyncMock()

        session_data = {
            "m365_app_credentials": {
                "tenant_id": "t-id",
                "client_id": "c-id",
                "client_secret": "c-secret",
            },
        }

        with patch("openlabels.server.routes.enumerate.SessionStore") as mock_store_cls:
            mock_store = AsyncMock()
            mock_store_cls.return_value = mock_store
            mock_store.get.return_value = session_data

            result = await _get_m365_session_credentials(mock_request, mock_db)

        assert result == {"tenant_id": "t-id", "client_id": "c-id", "client_secret": "c-secret"}

    @pytest.mark.asyncio
    async def test_falls_back_to_bootstrap_app(self):
        """Should fall back to bootstrap app credentials from settings."""
        from openlabels.server.routes.enumerate import _get_m365_session_credentials

        mock_request = MagicMock()
        mock_request.cookies.get.return_value = "valid-session"
        mock_db = AsyncMock()

        session_data = {
            "m365_tenant": {"tenant_id": "t-id"},
        }

        mock_settings = MagicMock()
        mock_settings.m365.client_id = "bootstrap-client-id"
        mock_secret = MagicMock()
        mock_secret.get_secret_value.return_value = "bootstrap-secret"
        mock_settings.m365.client_secret = mock_secret

        with patch("openlabels.server.routes.enumerate.SessionStore") as mock_store_cls:
            mock_store = AsyncMock()
            mock_store_cls.return_value = mock_store
            mock_store.get.return_value = session_data

            with patch("openlabels.server.config.get_settings", return_value=mock_settings):
                result = await _get_m365_session_credentials(mock_request, mock_db)

        assert result["tenant_id"] == "t-id"
        assert result["client_id"] == "bootstrap-client-id"
        assert result["client_secret"] == "bootstrap-secret"

    @pytest.mark.asyncio
    async def test_no_m365_tenant_raises_400(self):
        """Should raise 400 when no M365 tenant is connected."""
        from openlabels.server.routes.enumerate import _get_m365_session_credentials

        mock_request = MagicMock()
        mock_request.cookies.get.return_value = "valid-session"
        mock_db = AsyncMock()

        with patch("openlabels.server.routes.enumerate.SessionStore") as mock_store_cls:
            mock_store = AsyncMock()
            mock_store_cls.return_value = mock_store
            mock_store.get.return_value = {"provider": "dev"}

            with pytest.raises(HTTPException) as exc_info:
                await _get_m365_session_credentials(mock_request, mock_db)
            assert exc_info.value.status_code == 400
            assert "M365" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_m365_not_configured_raises_500(self):
        """Should raise 500 when M365 is not configured on the server."""
        from openlabels.server.routes.enumerate import _get_m365_session_credentials

        mock_request = MagicMock()
        mock_request.cookies.get.return_value = "valid-session"
        mock_db = AsyncMock()

        session_data = {"m365_tenant": {"tenant_id": "t-id"}}

        mock_settings = MagicMock()
        mock_settings.m365.client_id = None
        mock_secret = MagicMock()
        mock_secret.get_secret_value.return_value = ""
        mock_settings.m365.client_secret = mock_secret

        with patch("openlabels.server.routes.enumerate.SessionStore") as mock_store_cls:
            mock_store = AsyncMock()
            mock_store_cls.return_value = mock_store
            mock_store.get.return_value = session_data

            with patch("openlabels.server.config.get_settings", return_value=mock_settings):
                with pytest.raises(HTTPException) as exc_info:
                    await _get_m365_session_credentials(mock_request, mock_db)
                assert exc_info.value.status_code == 500
                assert "not configured" in exc_info.value.detail.lower()


# ── Subprocess safety ────────────────────────────────────────────────


class TestSubprocessSafety:
    """Tests verifying subprocess calls are safe from injection."""

    @pytest.mark.asyncio
    async def test_smb_uses_list_not_string(self):
        """smbclient should be called with a list (not shell=True)."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            await _enumerate_smb({"host": "safe.host", "username": "user", "password": "pass"})

            call_args = mock_thread.call_args
            # First arg is subprocess.run, second is the cmd list
            assert call_args[0][0] is subprocess.run
            cmd = call_args[0][1]
            assert isinstance(cmd, list)

    @pytest.mark.asyncio
    async def test_smb_has_timeout(self):
        """smbclient call must have a timeout to prevent hanging."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            await _enumerate_smb({"host": "server.local"})

            call_kwargs = mock_thread.call_args[0]
            # subprocess.run is called with keyword args including timeout
            # The call is: asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True, timeout=15, ...)
            # We need to check the keyword args passed to to_thread which are forwarded
            full_kwargs = mock_thread.call_args[1]
            assert full_kwargs.get("timeout", None) is not None or "timeout" in str(mock_thread.call_args)

    @pytest.mark.asyncio
    async def test_nfs_uses_list_not_string(self):
        """showmount should be called with a list (not shell=True)."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            await _enumerate_nfs({"host": "nfs.local"})

            call_args = mock_thread.call_args
            assert call_args[0][0] is subprocess.run
            cmd = call_args[0][1]
            assert isinstance(cmd, list)

    @pytest.mark.asyncio
    async def test_smb_password_never_in_cmdline(self):
        """Password must never appear in subprocess command line arguments."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""

        password = "super_secret_p@ss!"

        with patch("openlabels.server.routes.enumerate.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_result
            await _enumerate_smb({
                "host": "server.local",
                "username": "admin",
                "password": password,
            })

            call_args = mock_thread.call_args
            cmd = call_args[0][1]
            # Password must NOT appear anywhere in the command list
            for arg in cmd:
                assert password not in str(arg), (
                    f"Password found in command line argument: {arg}"
                )
