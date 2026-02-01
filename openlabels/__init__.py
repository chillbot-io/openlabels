"""
OpenLabels - Universal Data Risk Scoring.

Labels are the primitive. Risk is derived.

Quick Start:
    >>> from openlabels import Client
    >>> client = Client()
    >>> result = client.score_file("document.pdf")
    >>> print(f"Risk: {result.score}/100 ({result.tier})")

For cloud DLP integration:
    >>> from openlabels.adapters import MacieAdapter
    >>> adapter = MacieAdapter()
    >>> normalized = adapter.extract(macie_findings, s3_metadata)
    >>> result = client.score_from_adapters([normalized])

Working with labels:
    >>> from openlabels import Label, LabelSet
    >>> from openlabels.output import read_label, write_label
    >>>
    >>> # Read a label from a file (embedded or virtual)
    >>> result = read_label("document.pdf")
    >>> if result.label_set:
    ...     print(f"Found {len(result.label_set.labels)} labels")
    >>>
    >>> # Write a label (auto-selects transport)
    >>> success, transport = write_label("data.csv", label_set)

Architecture:
    The Client is a facade over focused components. For direct access:
    >>> from openlabels import Context
    >>> from openlabels.components import Scorer, Scanner
    >>>
    >>> ctx = Context()
    >>> scorer = Scorer(ctx)
    >>> result = scorer.score_text("SSN: 123-45-6789")
"""

__version__ = "0.1.0"

from .client import Client
from .context import Context, get_default_context, reset_default_context
from .core.scorer import ScoringResult
from .core.labels import (
    Label,
    LabelSet,
    VirtualLabelPointer,
    generate_label_id,
    compute_content_hash,
    compute_value_hash,
)

__all__ = [
    # Client
    "Client",
    "ScoringResult",
    # Context (dependency injection)
    "Context",
    "get_default_context",
    "reset_default_context",
    # Labels
    "Label",
    "LabelSet",
    "VirtualLabelPointer",
    "generate_label_id",
    "compute_content_hash",
    "compute_value_hash",
    # Version
    "__version__",
]
