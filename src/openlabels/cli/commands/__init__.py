"""CLI command modules."""

from openlabels.cli.commands.catalog import catalog
from openlabels.cli.commands.classify import classify
from openlabels.cli.commands.config import config
from openlabels.cli.commands.db import db
from openlabels.cli.commands.doctor import doctor
from openlabels.cli.commands.export import export
from openlabels.cli.commands.find import find
from openlabels.cli.commands.heatmap import heatmap
from openlabels.cli.commands.index import index
from openlabels.cli.commands.labels import labels
from openlabels.cli.commands.models import models
from openlabels.cli.commands.monitor import monitor
from openlabels.cli.commands.remediation import lock_down_cmd, quarantine
from openlabels.cli.commands.report import report
from openlabels.cli.commands.scan import scan
from openlabels.cli.commands.server import serve, worker
from openlabels.cli.commands.system import backup, restore, status
from openlabels.cli.commands.target import target
from openlabels.cli.commands.user import user

__all__ = [
    "serve",
    "worker",
    "db",
    "config",
    "user",
    "target",
    "scan",
    "labels",
    "export",
    "monitor",
    "catalog",
    "index",
    "classify",
    "find",
    "report",
    "heatmap",
    "quarantine",
    "lock_down_cmd",
    "status",
    "backup",
    "restore",
    "models",
    "doctor",
]
