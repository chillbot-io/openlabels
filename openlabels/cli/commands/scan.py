"""
OpenLabels scan command.

Scan local files and directories for sensitive data and compute risk scores.
Supports parallel processing for improved performance.

Usage:
    openlabels scan <path>
    openlabels scan ./data --recursive
    openlabels scan /path/to/file.csv
    openlabels scan ./data -r --workers 8
"""

import argparse
import json
import os
import stat as stat_module
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator, Optional, Dict, Any, List
from dataclasses import dataclass

from openlabels import Client
from openlabels.core.scorer import ScoringResult
from openlabels.cli.output import echo, error, success, dim, progress, divider, console
from openlabels.logging_config import get_logger, get_audit_logger

logger = get_logger(__name__)
audit = get_audit_logger()

# Default number of parallel workers
DEFAULT_WORKERS = min(os.cpu_count() or 4, 8)


# Risk tier to rich color mapping
TIER_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "yellow",
    "MEDIUM": "orange3",
    "LOW": "green",
    "MINIMAL": "dim",
}


@dataclass
class ScanResult:
    """Result of scanning a single file."""
    path: str
    score: int
    tier: str
    entities: Dict[str, int]
    exposure: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "path": self.path,
            "score": self.score,
            "tier": self.tier,
            "entities": self.entities,
            "exposure": self.exposure,
            "error": self.error,
        }


def scan_file(
    path: Path,
    client: Client,
    exposure: str = "PRIVATE",
) -> ScanResult:
    """Scan a single file and return result."""
    try:
        # First detect to get entity counts
        from openlabels.adapters.scanner import detect_file as scanner_detect

        detection = scanner_detect(path)
        entities = detection.entity_counts

        # Then score
        result = client.score_file(path, exposure=exposure)

        return ScanResult(
            path=str(path),
            score=result.score,
            tier=result.tier.value if hasattr(result.tier, 'value') else str(result.tier),
            entities=entities,
            exposure=exposure,
        )
    except (OSError, ValueError) as e:
        logger.warning(f"Failed to scan {path}: {e}")
        return ScanResult(
            path=str(path),
            score=0,
            tier="UNKNOWN",
            entities={},
            exposure=exposure,
            error=str(e),
        )


def collect_files(
    path: Path,
    recursive: bool = False,
    extensions: Optional[List[str]] = None,
) -> List[Path]:
    """Collect all files to scan from a directory."""
    if recursive:
        files = list(path.rglob("*"))
    else:
        files = list(path.glob("*"))

    def is_regular_file(p):  # TOCTOU-001: use lstat
        try:
            return stat_module.S_ISREG(p.lstat().st_mode)
        except OSError:
            return False

    files = [f for f in files if is_regular_file(f)]

    # Apply extension filter
    if extensions:
        exts = {e.lower().lstrip(".") for e in extensions}
        files = [f for f in files if f.suffix.lower().lstrip(".") in exts]

    return sorted(files)


def scan_directory(
    path: Path,
    client: Client,
    recursive: bool = False,
    exposure: str = "PRIVATE",
    extensions: Optional[List[str]] = None,
) -> Iterator[ScanResult]:
    """Scan all files in a directory (sequential)."""
    files = collect_files(path, recursive, extensions)
    for file_path in files:
        yield scan_file(file_path, client, exposure)


def scan_directory_parallel(
    files: List[Path],
    exposure: str = "PRIVATE",
    max_workers: int = DEFAULT_WORKERS,
    callback=None,
) -> List[ScanResult]:
    """Scan files in parallel using ThreadPoolExecutor.

    Args:
        files: List of file paths to scan
        exposure: Exposure level for scoring
        max_workers: Number of parallel workers
        callback: Optional callback(result) called for each completed file

    Returns:
        List of ScanResult objects
    """
    if not files:
        return []

    results = []
    results_lock = threading.Lock()

    # Thread-local storage for Client instances
    thread_local = threading.local()

    def get_thread_client():
        """Get or create a Client for the current thread."""
        if not hasattr(thread_local, 'client'):
            thread_local.client = Client(default_exposure=exposure)
        return thread_local.client

    def scan_task(file_path: Path) -> ScanResult:
        """Scan a single file in the thread pool."""
        client = get_thread_client()
        return scan_file(file_path, client, exposure)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_task, fp): fp for fp in files}

        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as e:
                file_path = futures[future]
                logger.warning(f"Failed to scan {file_path}: {e}")
                result = ScanResult(
                    path=str(file_path),
                    score=0,
                    tier="UNKNOWN",
                    entities={},
                    exposure=exposure,
                    error=str(e),
                )

            with results_lock:
                results.append(result)

            if callback:
                callback(result)

    return results


def format_scan_result_rich(result: ScanResult) -> None:
    """Print a scan result using rich formatting."""
    # Handle Optional score/tier fields
    tier_str = result.tier if result.tier is not None else "N/A"
    score_str = str(result.score) if result.score is not None else "N/A"
    color = TIER_COLORS.get(result.tier, "")

    if result.error:
        console.print(f"{result.path}: [red]ERROR[/red] - {result.error}")
        return

    entities_str = ", ".join(
        f"{k}({v})" for k, v in sorted(result.entities.items())
    ) if result.entities else "none"

    console.print(
        f"{result.path}: [{color}]{score_str:>3}[/{color}] ({tier_str:<8}) [{entities_str}]"
    )


def cmd_scan(args) -> int:
    """Execute the scan command with parallel processing."""
    path = Path(args.path)
    max_workers = getattr(args, 'workers', DEFAULT_WORKERS)

    if not path.exists():
        error(f"Path not found: {path}")
        return 1

    logger.info(f"Starting scan", extra={
        "path": str(path),
        "recursive": args.recursive,
        "exposure": args.exposure,
        "workers": max_workers,
    })

    # Audit log scan start
    audit.scan_start(path=str(path), recursive=args.recursive, exposure=args.exposure)

    results = []
    total_files = 0
    files_with_risk = 0
    max_score = 0

    def is_regular_file_check(p):  # TOCTOU-001: use lstat
        try:
            return stat_module.S_ISREG(p.lstat().st_mode)
        except OSError:
            return False

    if is_regular_file_check(path):
        # Single file - no parallelism needed
        client = Client(default_exposure=args.exposure)
        result = scan_file(path, client, args.exposure)
        results.append(result)
        total_files = 1
        if result.score > 0:
            files_with_risk = 1
            max_score = result.score

        if args.format == "text" and not args.quiet:
            format_scan_result_rich(result)
    else:
        # Directory scan with parallel processing
        extensions = args.extensions.split(",") if args.extensions else None

        # Collect files
        all_files = collect_files(path, args.recursive, extensions)

        if not all_files:
            echo("No files to scan")
            return 0

        # Progress tracking with thread safety
        progress_lock = threading.Lock()
        completed = [0]  # Use list for mutability in closure

        def on_result(result: ScanResult):
            """Callback for each completed scan."""
            nonlocal files_with_risk, max_score

            with progress_lock:
                completed[0] += 1
                if result.score > 0:
                    files_with_risk += 1
                    max_score = max(max_score, result.score)

                # Print progress for text format
                if args.format == "text" and not args.quiet:
                    format_scan_result_rich(result)

                p.advance()

        with progress("Scanning files", total=len(all_files)) as p:
            if max_workers == 1:
                # Sequential mode
                client = Client(default_exposure=args.exposure)
                for file_path in all_files:
                    result = scan_file(file_path, client, args.exposure)
                    results.append(result)
                    on_result(result)
            else:
                # Parallel mode
                results = scan_directory_parallel(
                    all_files,
                    exposure=args.exposure,
                    max_workers=max_workers,
                    callback=on_result,
                )

        total_files = len(results)

    # Output results
    if args.format == "json":
        output = {
            "summary": {
                "total_files": total_files,
                "files_with_risk": files_with_risk,
                "max_score": max_score,
            },
            "results": [r.to_dict() for r in results],
        }
        echo(json.dumps(output, indent=2))

    elif args.format == "jsonl":
        for result in results:
            # Use print() directly to avoid Rich console wrapping
            print(json.dumps(result.to_dict()))

    # Print summary for text format
    if args.format == "text":
        echo("")
        divider()
        echo(f"Scanned: {total_files} files")
        if files_with_risk > 0:
            echo(f"At risk: [yellow]{files_with_risk}[/yellow] files")
        else:
            success(f"At risk: 0 files")
        echo(f"Max score: {max_score}")

    logger.info(f"Scan complete", extra={
        "total_files": total_files,
        "files_with_risk": files_with_risk,
        "max_score": max_score,
    })

    # Audit log scan complete
    audit.scan_complete(
        path=str(path),
        files_scanned=total_files,
        files_with_risk=files_with_risk,
        max_score=max_score,
    )

    # Return exit code based on threshold
    if args.fail_above and max_score > args.fail_above:
        return 1

    return 0


def add_scan_parser(subparsers):
    """Add the scan subparser."""
    parser = subparsers.add_parser(
        "scan",
        help="Scan files for sensitive data and compute risk scores",
    )
    parser.add_argument(
        "path",
        help="File or directory to scan",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Scan subdirectories",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "jsonl"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-above",
        type=int,
        metavar="SCORE",
        help="Exit code 1 if any file scores above threshold (for CI)",
    )
    parser.add_argument(
        "--workers", "-j",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help=f"Number of parallel workers (default: {DEFAULT_WORKERS})",
    )
    # Hidden options for power users
    parser.add_argument(
        "--exposure", "-e",
        choices=["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"],
        default="PRIVATE",
        help=argparse.SUPPRESS,  # Hidden: always PRIVATE for simplicity
    )
    parser.add_argument(
        "--extensions",
        help=argparse.SUPPRESS,  # Hidden: scan all files
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help=argparse.SUPPRESS,  # Hidden: use global --quiet
    )
    parser.set_defaults(func=cmd_scan)

    return parser
