"""
OpenLabels Client.

High-level API for scoring files and objects.

The Client provides a unified interface for:
- Scoring individual files or text
- Scanning directories recursively
- Finding files matching filter criteria
- Data management operations (quarantine, move, delete)
- Generating reports

Example:
    >>> from openlabels import Client
    >>>
    >>> client = Client()
    >>>
    >>> # Score a single file
    >>> result = client.score_file("data.csv")
    >>> print(f"Risk: {result.score} ({result.tier.value})")
    >>>
    >>> # Scan a directory
    >>> for item in client.scan("/data", recursive=True):
    ...     if item.score >= 70:
    ...         print(f"High risk: {item.path}")
    >>>
    >>> # Find and quarantine high-risk files
    >>> client.quarantine(
    ...     "/data",
    ...     "/quarantine",
    ...     min_score=80,
    ...     recursive=True,
    ... )

Architecture:
    Client is a thin facade that composes focused components:
    - Scorer: Risk scoring operations
    - Scanner: File/directory scanning
    - FileOps: File operations (quarantine, move, delete)
    - Reporter: Report generation

    Each component can also be used independently:
    >>> from openlabels import Context
    >>> from openlabels.components import Scorer
    >>>
    >>> ctx = Context()
    >>> scorer = Scorer(ctx)
    >>> result = scorer.score_text("SSN: 123-45-6789")
"""

from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Union

from .context import Context, get_default_context
from .adapters.base import Adapter, NormalizedInput
from .core.scorer import ScoringResult
from .core.types import (
    ScanResult,
    FilterCriteria,
    OperationResult,
    TreeNode,
    ReportFormat,
    ReportConfig,
)
from .components.scorer import Scorer
from .components.scanner import Scanner
from .components.fileops import FileOps, QuarantineResult, DeleteResult
from .components.reporter import Reporter

# Re-export result types for backward compatibility
__all__ = [
    "Client",
    "QuarantineResult",
    "DeleteResult",
]


class Client:
    """
    High-level OpenLabels client.

    A facade that composes Scorer, Scanner, FileOps, and Reporter components.

    Example usage:
        >>> from openlabels import Client
        >>>
        >>> client = Client()
        >>> result = client.score_file("sensitive_data.pdf")
        >>> print(f"Risk score: {result.score} ({result.tier.value})")

    For cloud adapters:
        >>> from openlabels.adapters import MacieAdapter
        >>>
        >>> adapter = MacieAdapter()
        >>> normalized = adapter.extract(macie_findings, s3_metadata)
        >>> result = client.score_from_adapters([normalized])

    For direct component access:
        >>> client = Client()
        >>> # Access underlying components
        >>> client.scorer.score_text("test")
        >>> client.scanner.scan("/data")
    """

    def __init__(
        self,
        context: Optional[Context] = None,
        default_exposure: str = "PRIVATE",
    ):
        """
        Initialize the client.

        Args:
            context: Optional Context for dependency injection.
                    If None, uses the default shared context.
            default_exposure: Default exposure level when not specified.
                             One of: PRIVATE, INTERNAL, ORG_WIDE, PUBLIC

        Note:
            If both context and a non-default exposure are specified,
            the exposure from the passed context takes precedence.
        """
        if context is None:
            # No context provided - create one with the specified exposure
            if default_exposure.upper() != "PRIVATE":
                context = Context(default_exposure=default_exposure.upper())
            else:
                context = get_default_context(warn=False)
        # If context was provided, use it as-is (don't override its exposure)

        self._ctx = context

        # Initialize components
        self._scorer = Scorer(context)
        self._scanner = Scanner(context, self._scorer)
        self._fileops = FileOps(context, self._scanner)
        self._reporter = Reporter(context, self._scanner)

    @property
    def context(self) -> Context:
        """Access the underlying context."""
        return self._ctx

    @property
    def scorer(self) -> Scorer:
        """Access the scorer component."""
        return self._scorer

    @property
    def scanner(self) -> Scanner:
        """Access the scanner component."""
        return self._scanner

    @property
    def fileops(self) -> FileOps:
        """Access the file operations component."""
        return self._fileops

    @property
    def reporter(self) -> Reporter:
        """Access the reporter component."""
        return self._reporter

    @property
    def default_exposure(self) -> str:
        """Get the default exposure level."""
        return self._ctx.default_exposure

    def score_file(
        self,
        path: Union[str, Path],
        adapters: Optional[List[Adapter]] = None,
        exposure: Optional[str] = None,
    ) -> ScoringResult:
        """
        Score a local file for data risk.

        If no adapters specified, uses the built-in scanner for detection.

        Args:
            path: Path to file to scan
            adapters: Optional list of adapters to use. If None, uses scanner.
            exposure: Exposure level override (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC).

        Returns:
            ScoringResult with score, tier, and breakdown
        """
        return self._scorer.score_file(path, adapters=adapters, exposure=exposure)

    def score_text(
        self,
        text: str,
        exposure: Optional[str] = None,
    ) -> ScoringResult:
        """
        Score text content for data risk.

        Args:
            text: Text to scan for sensitive data
            exposure: Exposure level (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC)

        Returns:
            ScoringResult with score, tier, and breakdown
        """
        return self._scorer.score_text(text, exposure=exposure)

    def score_from_adapters(
        self,
        inputs: List[NormalizedInput],
        exposure: Optional[str] = None,
    ) -> ScoringResult:
        """
        Score from pre-extracted adapter outputs.

        Args:
            inputs: List of NormalizedInput from adapters
            exposure: Exposure level override.

        Returns:
            ScoringResult with score, tier, and breakdown
        """
        return self._scorer.score_from_adapters(inputs, exposure=exposure)

    def scan(
        self,
        path: Union[str, Path],
        recursive: bool = True,
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        include_hidden: bool = False,
        max_files: Optional[int] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Iterator[ScanResult]:
        """
        Scan files and yield results as they complete.

        Args:
            path: File or directory to scan
            recursive: Recurse into subdirectories (default True)
            filter_criteria: Optional FilterCriteria to filter results
            filter_expr: Optional filter expression string (e.g., "score > 70")
            include_hidden: Include hidden files/directories (default False)
            max_files: Maximum number of files to scan (None = unlimited)
            on_progress: Optional callback for progress updates

        Yields:
            ScanResult for each file scanned
        """
        return self._scanner.scan(
            path,
            recursive=recursive,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
            include_hidden=include_hidden,
            max_files=max_files,
            on_progress=on_progress,
        )

    def find(
        self,
        path: Union[str, Path],
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        recursive: bool = True,
        limit: Optional[int] = None,
    ) -> Iterator[ScanResult]:
        """
        Find files matching criteria.

        Args:
            path: Directory to search
            filter_criteria: Filter criteria
            filter_expr: Filter expression string
            recursive: Recurse into subdirectories
            limit: Maximum results to return

        Yields:
            ScanResult for matching files
        """
        return self._scanner.find(
            path,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
            recursive=recursive,
            limit=limit,
        )

    def scan_tree(
        self,
        path: Union[str, Path],
        max_depth: Optional[int] = None,
    ) -> TreeNode:
        """
        Build a risk tree for directory visualization.

        Args:
            path: Root directory to scan
            max_depth: Maximum depth to recurse (None = unlimited)

        Returns:
            TreeNode representing the directory tree with risk data
        """
        return self._scanner.scan_tree(path, max_depth=max_depth)

    def quarantine(
        self,
        source: Union[str, Path],
        destination: Union[str, Path],
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        min_score: Optional[int] = None,
        recursive: bool = True,
        dry_run: bool = False,
    ) -> QuarantineResult:
        """
        Move files matching criteria to quarantine.

        Args:
            source: Source directory to scan
            destination: Quarantine destination directory
            filter_criteria: Filter criteria for files to quarantine
            filter_expr: Filter expression string
            min_score: Minimum score to quarantine
            recursive: Recurse into subdirectories
            dry_run: If True, don't actually move files

        Returns:
            QuarantineResult with counts and moved file list
        """
        return self._fileops.quarantine(
            source,
            destination,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
            min_score=min_score,
            recursive=recursive,
            dry_run=dry_run,
        )

    def move(
        self,
        source: Union[str, Path],
        destination: Union[str, Path],
    ) -> OperationResult:
        """
        Move a single file or directory.

        Args:
            source: Source path
            destination: Destination path

        Returns:
            OperationResult indicating success or failure
        """
        return self._fileops.move(source, destination)

    def delete(
        self,
        path: Union[str, Path],
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        min_score: Optional[int] = None,
        recursive: bool = True,
        confirm: bool = True,
        dry_run: bool = False,
    ) -> DeleteResult:
        """
        Delete files matching criteria.

        WARNING: This permanently deletes files. Use dry_run=True first.

        Args:
            path: Directory to scan for files to delete
            filter_criteria: Filter criteria
            filter_expr: Filter expression
            min_score: Minimum score to delete
            recursive: Recurse into subdirectories
            confirm: If True, requires explicit confirmation
            dry_run: If True, don't actually delete files

        Returns:
            DeleteResult with counts and deleted file list
        """
        return self._fileops.delete(
            path,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
            min_score=min_score,
            recursive=recursive,
            confirm=confirm,
            dry_run=dry_run,
        )

    def report(
        self,
        path: Union[str, Path],
        output: Optional[Union[str, Path]] = None,
        format: ReportFormat = ReportFormat.JSON,
        config: Optional[ReportConfig] = None,
        recursive: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate a risk report for a path.

        Args:
            path: Path to scan for report
            output: Optional output file path
            format: Report format (JSON, CSV, HTML, JSONL, MARKDOWN)
            config: Optional report configuration
            recursive: Recurse into subdirectories

        Returns:
            Report data as dictionary
        """
        return self._reporter.report(
            path,
            output=output,
            format=format,
            config=config,
            recursive=recursive,
        )
