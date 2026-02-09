"""
CLI command modules.

This module provides all CLI commands for OpenLabels, organized into logical groups.
"""

# Server commands
from openlabels.cli.commands.server import serve, worker, gui

# Database commands
from openlabels.cli.commands.db import db

# Configuration commands
from openlabels.cli.commands.config import config

# User management commands
from openlabels.cli.commands.user import user

# Target management commands
from openlabels.cli.commands.target import target

# Scan management commands
from openlabels.cli.commands.scan import scan

# Label management commands
from openlabels.cli.commands.labels import labels

# Export commands
from openlabels.cli.commands.export import export

# Local classification command
from openlabels.cli.commands.classify import classify

# Find command with filtering
from openlabels.cli.commands.find import find

# Report generation command
from openlabels.cli.commands.report import report

# Heatmap visualization command
from openlabels.cli.commands.heatmap import heatmap

# Remediation commands
from openlabels.cli.commands.remediation import quarantine, lock_down_cmd

# Monitoring commands
from openlabels.cli.commands.monitor import monitor

# Catalog management commands
from openlabels.cli.commands.catalog import catalog

# System commands
from openlabels.cli.commands.system import status, backup, restore

# Model management commands
from openlabels.cli.commands.models import models

# Diagnostic command
from openlabels.cli.commands.doctor import doctor


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
