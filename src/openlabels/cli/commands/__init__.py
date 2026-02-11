"""
CLI command modules.

This module provides all CLI commands for OpenLabels, organized into logical groups.
"""

# Server commands
# Catalog management commands
from openlabels.cli.commands.catalog import catalog

# Local classification command
from openlabels.cli.commands.classify import classify

# Configuration commands
from openlabels.cli.commands.config import config

# Database commands
from openlabels.cli.commands.db import db

# Diagnostic command
from openlabels.cli.commands.doctor import doctor

# Export commands
from openlabels.cli.commands.export import export

# Find command with filtering
from openlabels.cli.commands.find import find

# Directory tree index commands
from openlabels.cli.commands.index import index

# Heatmap visualization command
from openlabels.cli.commands.heatmap import heatmap

# Label management commands
from openlabels.cli.commands.labels import labels

# Model management commands
from openlabels.cli.commands.models import models

# Monitoring commands
from openlabels.cli.commands.monitor import monitor

# Remediation commands
from openlabels.cli.commands.remediation import lock_down_cmd, quarantine

# Report generation command
from openlabels.cli.commands.report import report

# Scan management commands
from openlabels.cli.commands.scan import scan
from openlabels.cli.commands.server import gui, serve, worker

# System commands
from openlabels.cli.commands.system import backup, restore, status

# Target management commands
from openlabels.cli.commands.target import target

# User management commands
from openlabels.cli.commands.user import user

__all__ = [
    # Server commands
    "serve",
    "worker",
    "gui",
    # Command groups
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
    # Standalone commands
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
