"""Build SIEM adapters from configuration settings."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from openlabels.export.adapters.base import SIEMAdapter

if TYPE_CHECKING:
    from openlabels.server.config import SIEMExportSettings

logger = logging.getLogger(__name__)


def build_adapters_from_settings(cfg: SIEMExportSettings) -> list[SIEMAdapter]:
    """Instantiate all configured SIEM adapters."""
    adapters: list[SIEMAdapter] = []

    if cfg.splunk_hec_url and cfg.splunk_hec_token:
        from openlabels.export.adapters.splunk import SplunkAdapter

        adapters.append(SplunkAdapter(
            hec_url=cfg.splunk_hec_url,
            hec_token=cfg.splunk_hec_token,
            index=cfg.splunk_index,
            sourcetype=cfg.splunk_sourcetype,
            verify_ssl=cfg.splunk_verify_ssl,
        ))
        logger.info("Configured Splunk HEC adapter")

    if cfg.sentinel_workspace_id and cfg.sentinel_shared_key:
        from openlabels.export.adapters.sentinel import SentinelAdapter

        adapters.append(SentinelAdapter(
            workspace_id=cfg.sentinel_workspace_id,
            shared_key=cfg.sentinel_shared_key,
            log_type=cfg.sentinel_log_type,
        ))
        logger.info("Configured Sentinel adapter")

    if cfg.qradar_syslog_host:
        from openlabels.export.adapters.qradar import QRadarAdapter

        adapters.append(QRadarAdapter(
            syslog_host=cfg.qradar_syslog_host,
            syslog_port=cfg.qradar_syslog_port,
            protocol=cfg.qradar_protocol,
            use_tls=cfg.qradar_use_tls,
            fmt=cfg.qradar_format,
        ))
        logger.info("Configured QRadar syslog adapter")

    if cfg.elastic_hosts:
        from openlabels.export.adapters.elastic import ElasticAdapter

        adapters.append(ElasticAdapter(
            hosts=cfg.elastic_hosts,
            api_key=cfg.elastic_api_key or None,
            username=cfg.elastic_username or None,
            password=cfg.elastic_password or None,
            index_prefix=cfg.elastic_index_prefix,
            verify_ssl=cfg.elastic_verify_ssl,
        ))
        logger.info("Configured Elastic adapter")

    if cfg.syslog_host:
        from openlabels.export.adapters.syslog_cef import SyslogCEFAdapter

        adapters.append(SyslogCEFAdapter(
            host=cfg.syslog_host,
            port=cfg.syslog_port,
            protocol=cfg.syslog_protocol,
            use_tls=cfg.syslog_use_tls,
        ))
        logger.info("Configured generic syslog CEF adapter")

    return adapters
