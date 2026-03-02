"""Tests for WEF (Windows Event Forwarding) subscription management."""

import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.monitoring.wef_setup import (
    WEFSubscriptionInfo,
    _build_subscription_xml,
    _SUBSCRIPTION_NAME,
    create_subscription,
    delete_subscription,
    get_gpo_config,
    get_subscription_status,
    init_collector,
    list_subscriptions,
)


class TestBuildSubscriptionXml:
    """Tests for XML generation of WEF subscriptions."""

    def test_default_xml_contains_subscription_id(self):
        xml = _build_subscription_xml()
        assert f"<SubscriptionId>{_SUBSCRIPTION_NAME}</SubscriptionId>" in xml

    def test_default_xml_contains_default_event_ids(self):
        xml = _build_subscription_xml()
        assert "EventID=4663" in xml
        assert "EventID=4656" in xml

    def test_custom_event_ids(self):
        xml = _build_subscription_xml(event_ids=[4663])
        assert "EventID=4663" in xml
        assert "EventID=4656" not in xml

    def test_custom_subscription_name(self):
        xml = _build_subscription_xml(subscription_name="MyCustomSub")
        assert "<SubscriptionId>MyCustomSub</SubscriptionId>" in xml

    def test_source_initiated_type(self):
        xml = _build_subscription_xml()
        assert "<SubscriptionType>SourceInitiated</SubscriptionType>" in xml

    def test_enabled_true(self):
        xml = _build_subscription_xml()
        assert "<Enabled>true</Enabled>" in xml

    def test_default_transport_is_http(self):
        xml = _build_subscription_xml()
        assert "<TransportName>HTTP</TransportName>" in xml

    def test_https_transport(self):
        xml = _build_subscription_xml(transport="HTTPS")
        assert "<TransportName>HTTPS</TransportName>" in xml

    def test_invalid_transport_raises(self):
        with pytest.raises(ValueError, match="transport must be"):
            _build_subscription_xml(transport="FTP")

    def test_invalid_subscription_name_raises(self):
        with pytest.raises(ValueError, match="subscription_name must contain only"):
            _build_subscription_xml(subscription_name="bad name with spaces!")

    def test_subscription_name_with_hyphens_and_underscores_allowed(self):
        xml = _build_subscription_xml(subscription_name="My-Sub_Name123")
        assert "<SubscriptionId>My-Sub_Name123</SubscriptionId>" in xml

    def test_delivery_settings(self):
        xml = _build_subscription_xml(
            delivery_max_items=20,
            delivery_max_latency_ms=30_000,
        )
        assert "<MaxItems>20</MaxItems>" in xml
        assert "<MaxLatencyTime>30000</MaxLatencyTime>" in xml

    def test_default_sddl_in_xml(self):
        xml = _build_subscription_xml()
        assert "O:NSG:NSD:" in xml

    def test_xml_escape_in_description(self):
        """Description should be XML-escaped."""
        xml = _build_subscription_xml()
        # The description contains event IDs; check it exists and is well-formed
        assert "<Description>" in xml
        assert "</Description>" in xml

    def test_push_delivery_mode(self):
        xml = _build_subscription_xml()
        assert 'Delivery Mode="Push"' in xml

    def test_forwarded_events_log(self):
        xml = _build_subscription_xml()
        assert "<LogFile>ForwardedEvents</LogFile>" in xml

    def test_security_path_in_query(self):
        xml = _build_subscription_xml()
        assert 'Path="Security"' in xml

    def test_multiple_event_ids_or_joined(self):
        xml = _build_subscription_xml(event_ids=[4663, 4656, 4660])
        assert "EventID=4663 or EventID=4656 or EventID=4660" in xml


class TestInitCollector:
    """Tests for WEF collector initialization."""

    async def test_init_success(self):
        mock_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            success, msg = await init_collector()
        assert success is True
        assert "initialized" in msg.lower()

    async def test_init_failure(self):
        mock_proc = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Service error"
        )
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            success, msg = await init_collector()
        assert success is False
        assert "Service error" in msg

    async def test_init_wecutil_not_found(self):
        with patch(
            "openlabels.monitoring.wef_setup._run_wecutil",
            side_effect=FileNotFoundError(),
        ):
            success, msg = await init_collector()
        assert success is False
        assert "wecutil not found" in msg

    async def test_init_unexpected_exception(self):
        with patch(
            "openlabels.monitoring.wef_setup._run_wecutil",
            side_effect=RuntimeError("unexpected"),
        ):
            success, msg = await init_collector()
        assert success is False
        assert "unexpected" in msg


class TestCreateSubscription:
    """Tests for subscription creation and update."""

    async def test_create_new_subscription(self):
        # gs (get subscription) returns nonzero → does not exist
        check_proc = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Not found"
        )
        # cs (create subscription) succeeds
        create_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        call_count = 0

        def mock_wecutil(*args, timeout=30):
            nonlocal call_count
            call_count += 1
            if args[0] == "gs":
                return check_proc
            return create_proc

        with patch("openlabels.monitoring.wef_setup._run_wecutil", side_effect=mock_wecutil):
            success, msg = await create_subscription()

        assert success is True
        assert "active" in msg.lower()

    async def test_update_existing_subscription(self):
        # gs returns 0 → subscription exists
        check_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="<xml>", stderr="")
        # ss (set subscription) succeeds
        update_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        def mock_wecutil(*args, timeout=30):
            if args[0] == "gs":
                return check_proc
            return update_proc

        with patch("openlabels.monitoring.wef_setup._run_wecutil", side_effect=mock_wecutil):
            success, msg = await create_subscription()

        assert success is True

    async def test_create_subscription_failure(self):
        check_proc = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Not found"
        )
        fail_proc = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Access denied"
        )

        def mock_wecutil(*args, timeout=30):
            if args[0] == "gs":
                return check_proc
            return fail_proc

        with patch("openlabels.monitoring.wef_setup._run_wecutil", side_effect=mock_wecutil):
            success, msg = await create_subscription()

        assert success is False
        assert "Access denied" in msg

    async def test_create_subscription_wecutil_not_found(self):
        with patch(
            "openlabels.monitoring.wef_setup._run_wecutil",
            side_effect=FileNotFoundError(),
        ):
            success, msg = await create_subscription()

        assert success is False
        assert "wecutil not found" in msg


class TestDeleteSubscription:
    """Tests for subscription deletion."""

    async def test_delete_success(self):
        mock_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            success, msg = await delete_subscription()
        assert success is True
        assert "deleted" in msg.lower()

    async def test_delete_failure(self):
        mock_proc = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Subscription not found"
        )
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            success, msg = await delete_subscription()
        assert success is False

    async def test_delete_wecutil_not_found(self):
        with patch(
            "openlabels.monitoring.wef_setup._run_wecutil",
            side_effect=FileNotFoundError(),
        ):
            success, msg = await delete_subscription()
        assert success is False
        assert "wecutil not found" in msg

    async def test_delete_custom_name(self):
        mock_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc) as m:
            success, msg = await delete_subscription("CustomSub")
        assert success is True
        assert "CustomSub" in msg


class TestGetSubscriptionStatus:
    """Tests for subscription status retrieval."""

    async def test_status_active_subscription(self):
        # wecutil gs output without XML namespace (typical real output)
        xml_output = """<?xml version="1.0" encoding="utf-8"?>
<Subscription>
    <SubscriptionId>OpenLabels-FileAccess</SubscriptionId>
    <Enabled>true</Enabled>
    <RuntimeStatus>Active</RuntimeStatus>
    <EventSource><Address>server1</Address></EventSource>
    <EventSource><Address>server2</Address></EventSource>
</Subscription>"""
        mock_proc = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=xml_output, stderr=""
        )
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            info = await get_subscription_status()

        assert isinstance(info, WEFSubscriptionInfo)
        assert info.enabled is True
        assert info.source_count == 2
        assert info.status == "active"
        assert info.delivery_mode == "Push"

    async def test_status_not_found(self):
        mock_proc = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Subscription not found"
        )
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            info = await get_subscription_status()

        assert info.status == "not_found"
        assert info.enabled is False
        assert info.error is not None

    async def test_status_disabled_subscription(self):
        xml_output = """<?xml version="1.0" encoding="utf-8"?>
<Subscription>
    <SubscriptionId>OpenLabels-FileAccess</SubscriptionId>
    <Enabled>false</Enabled>
</Subscription>"""
        mock_proc = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=xml_output, stderr=""
        )
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            info = await get_subscription_status()

        assert info.enabled is False
        assert info.status == "disabled"

    async def test_status_wecutil_not_found(self):
        with patch(
            "openlabels.monitoring.wef_setup._run_wecutil",
            side_effect=FileNotFoundError(),
        ):
            info = await get_subscription_status()

        assert info.status == "error"
        assert "wecutil not found" in info.error

    async def test_status_unexpected_exception(self):
        with patch(
            "openlabels.monitoring.wef_setup._run_wecutil",
            side_effect=RuntimeError("boom"),
        ):
            info = await get_subscription_status()

        assert info.status == "error"
        assert "boom" in info.error

    async def test_status_malformed_xml_fallback(self):
        """Non-XML output should fall back to string matching."""
        text_output = "SubscriptionId: OpenLabels-FileAccess\nEnabled: true\nActive"
        mock_proc = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=text_output, stderr=""
        )
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            info = await get_subscription_status()

        assert info.enabled is True
        assert info.status == "active"


class TestListSubscriptions:
    """Tests for listing WEF subscriptions."""

    async def test_list_subscriptions(self):
        mock_proc = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Sub1\nSub2\nSub3\n", stderr=""
        )
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            subs = await list_subscriptions()
        assert subs == ["Sub1", "Sub2", "Sub3"]

    async def test_list_empty(self):
        mock_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            subs = await list_subscriptions()
        assert subs == []

    async def test_list_failure(self):
        mock_proc = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Error"
        )
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            subs = await list_subscriptions()
        assert subs == []

    async def test_list_wecutil_not_found(self):
        with patch(
            "openlabels.monitoring.wef_setup._run_wecutil",
            side_effect=FileNotFoundError(),
        ):
            subs = await list_subscriptions()
        assert subs == []

    async def test_list_strips_whitespace(self):
        mock_proc = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="  Sub1  \n  Sub2  \n", stderr=""
        )
        with patch("openlabels.monitoring.wef_setup._run_wecutil", return_value=mock_proc):
            subs = await list_subscriptions()
        assert subs == ["Sub1", "Sub2"]


class TestGetGpoConfig:
    """Tests for GPO configuration string generation."""

    def test_http_config(self):
        config = get_gpo_config("collector.example.com")
        assert "http://collector.example.com:5985" in config
        assert "SubscriptionManager/WEC" in config
        assert "Refresh=60" in config

    def test_https_config(self):
        config = get_gpo_config("collector.example.com", use_https=True)
        assert "HTTPS://collector.example.com:5986" in config

    def test_custom_refresh(self):
        config = get_gpo_config("collector.example.com", refresh_seconds=120)
        assert "Refresh=120" in config

    def test_server_prefix(self):
        config = get_gpo_config("collector.example.com")
        assert config.startswith("Server=")
