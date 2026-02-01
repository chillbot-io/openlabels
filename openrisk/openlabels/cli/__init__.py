"""
OpenLabels CLI.

Command-line interface for scanning, finding, and managing data risk.

Usage:
    openlabels scan <path>                     # Scan and score files
    openlabels find <path> --where "<filter>"  # Find matching files
    openlabels quarantine <src> --to <dst>     # Move risky files
    openlabels report <path> --format html     # Generate reports
    openlabels heatmap <path>                  # Visual risk heatmap
"""

from .main import main
from .filter import Filter, parse_filter, matches_filter, FilterBuilder

# CLI display constants
MAX_PREVIEW_RESULTS = 20  # Max results to show in preview/dry-run mode

__all__ = [
    "main",
    "Filter",
    "parse_filter",
    "matches_filter",
    "FilterBuilder",
    "MAX_PREVIEW_RESULTS",
]
