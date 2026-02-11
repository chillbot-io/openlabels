"""Phase K integration tests — config, setup, adapter protocol compliance."""

from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import patch

import pytest

from openlabels.export.adapters.base import SIEMAdapter


# ── Configuration ────────────────────────────────────────────────────

class TestSIEMExportSettings:
    def test_defaults(self):
        from openlabels.server.config import SIEMExportSettings

        cfg = SIEMExportSettings()
        assert cfg.enabled is False
        assert cfg.mode == "post_scan"
        assert cfg.periodic_interval_seconds == 300
        assert cfg.splunk_hec_url == ""
        assert cfg.sentinel_workspace_id == ""
        assert cfg.qradar_syslog_host == ""
        assert cfg.elastic_hosts == []
        assert cfg.syslog_host == ""
        assert cfg.export_record_types == ["scan_result", "policy_violation"]

    def test_in_main_settings(self):
        from openlabels.server.config import Settings

        # Verify siem_export field exists on Settings
        assert hasattr(Settings, "model_fields")
        assert "siem_export" in Settings.model_fields


# ── Adapter builder ──────────────────────────────────────────────────

class TestBuildAdaptersFromSettings:
    def test_no_adapters_when_empty(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        cfg = SIEMExportSettings()
        adapters = build_adapters_from_settings(cfg)
        assert adapters == []

    def test_splunk_adapter_created(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        cfg = SIEMExportSettings(
            splunk_hec_url="https://splunk:8088",
            splunk_hec_token="my-token",
        )
        adapters = build_adapters_from_settings(cfg)
        assert len(adapters) == 1
        assert adapters[0].format_name() == "splunk"

    def test_multiple_adapters_created(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        cfg = SIEMExportSettings(
            splunk_hec_url="https://splunk:8088",
            splunk_hec_token="tok",
            qradar_syslog_host="qradar.local",
            syslog_host="syslog.local",
        )
        adapters = build_adapters_from_settings(cfg)
        names = {a.format_name() for a in adapters}
        assert names == {"splunk", "qradar", "syslog_cef"}

    def test_sentinel_needs_both_fields(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        # Only workspace_id, no shared_key -> no adapter
        cfg = SIEMExportSettings(sentinel_workspace_id="ws123")
        adapters = build_adapters_from_settings(cfg)
        assert len(adapters) == 0

    def test_elastic_adapter_created(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        cfg = SIEMExportSettings(elastic_hosts=["https://es:9200"])
        adapters = build_adapters_from_settings(cfg)
        assert len(adapters) == 1
        assert adapters[0].format_name() == "elastic"

    def test_sentinel_created_with_both_fields(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        key = base64.b64encode(b"0" * 64).decode()
        cfg = SIEMExportSettings(
            sentinel_workspace_id="ws123",
            sentinel_shared_key=key,
        )
        adapters = build_adapters_from_settings(cfg)
        assert len(adapters) == 1
        assert adapters[0].format_name() == "sentinel"

    def test_all_five_adapters_created(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        key = base64.b64encode(b"0" * 64).decode()
        cfg = SIEMExportSettings(
            splunk_hec_url="https://splunk:8088",
            splunk_hec_token="tok",
            sentinel_workspace_id="ws123",
            sentinel_shared_key=key,
            qradar_syslog_host="qradar.local",
            elastic_hosts=["https://es:9200"],
            syslog_host="syslog.local",
        )
        adapters = build_adapters_from_settings(cfg)
        names = {a.format_name() for a in adapters}
        assert names == {"splunk", "sentinel", "qradar", "elastic", "syslog_cef"}


# ── Adapter protocol compliance ──────────────────────────────────────

class TestAdapterProtocolCompliance:
    """Verify all concrete adapters satisfy the SIEMAdapter protocol."""

    def test_splunk_implements_protocol(self):
        from openlabels.export.adapters.splunk import SplunkAdapter
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")
        assert isinstance(adapter, SIEMAdapter)
        assert adapter.format_name() == "splunk"

    def test_sentinel_implements_protocol(self):
        from openlabels.export.adapters.sentinel import SentinelAdapter
        key = base64.b64encode(b"0" * 64).decode()
        adapter = SentinelAdapter(workspace_id="ws123", shared_key=key)
        assert isinstance(adapter, SIEMAdapter)
        assert adapter.format_name() == "sentinel"

    def test_qradar_implements_protocol(self):
        from openlabels.export.adapters.qradar import QRadarAdapter
        adapter = QRadarAdapter(syslog_host="qradar.local")
        assert isinstance(adapter, SIEMAdapter)
        assert adapter.format_name() == "qradar"

    def test_elastic_implements_protocol(self):
        from openlabels.export.adapters.elastic import ElasticAdapter
        adapter = ElasticAdapter(hosts=["https://es:9200"])
        assert isinstance(adapter, SIEMAdapter)
        assert adapter.format_name() == "elastic"

    def test_syslog_cef_implements_protocol(self):
        from openlabels.export.adapters.syslog_cef import SyslogCEFAdapter
        adapter = SyslogCEFAdapter(host="syslog.local")
        assert isinstance(adapter, SIEMAdapter)
        assert adapter.format_name() == "syslog_cef"
