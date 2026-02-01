"""
OpenLabels Scanner Component.

Handles file and directory scanning operations.
"""

import fnmatch
import logging
import stat as stat_module
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, Optional, Union, TYPE_CHECKING

from ..core.scorer import score as score_entities
from ..core.types import ScanResult, FilterCriteria, TreeNode
from ..cli.filter import Filter, parse_filter
from ..utils.hashing import quick_hash

if TYPE_CHECKING:
    from ..context import Context
    from .scorer import Scorer

logger = logging.getLogger(__name__)


class FileModifiedError(Exception):
    """Raised when a file is modified during scanning."""
    pass


class Scanner:
    """
    File/directory scanning component.

    Handles:
    - scan(): Scan files and yield results
    - find(): Find files matching criteria
    - scan_tree(): Build risk tree for visualization

    Example:
        >>> from openlabels import Context
        >>> from openlabels.components import Scorer, Scanner
        >>>
        >>> ctx = Context()
        >>> scorer = Scorer(ctx)
        >>> scanner = Scanner(ctx, scorer)
        >>> for result in scanner.scan("/data"):
        ...     print(f"{result.path}: {result.score}")
    """

    def __init__(self, context: "Context", scorer: "Scorer"):
        self._ctx = context
        self._scorer = scorer

    @property
    def default_exposure(self) -> str:
        return self._ctx.default_exposure

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
            recursive: Recurse into subdirectories
            filter_criteria: Optional FilterCriteria to filter results
            filter_expr: Optional filter expression string
            include_hidden: Include hidden files/directories
            max_files: Maximum number of files to scan
            on_progress: Optional callback for progress updates

        Yields:
            ScanResult for each file scanned
        """
        path = Path(path)

        try:
            st = path.lstat()  # TOCTOU-001: atomic stat
            is_regular_file = stat_module.S_ISREG(st.st_mode)
            is_directory = stat_module.S_ISDIR(st.st_mode)
            is_symlink = stat_module.S_ISLNK(st.st_mode)
        except FileNotFoundError:
            raise FileNotFoundError(f"Path not found: {path}")

        if is_symlink:  # Reject symlinks
            raise ValueError(f"Symlinks not allowed for security: {path}")

        # Must be either a file or directory
        if not is_regular_file and not is_directory:
            raise ValueError(f"Not a file or directory: {path}")

        filter_obj = parse_filter(filter_expr) if filter_expr else None

        # Single file
        if is_regular_file:
            result = self._scan_single_file(path)
            if self._matches_filter(result, filter_criteria, filter_obj):
                yield result
            return

        # Directory
        for file_path in self._iter_files(path, recursive, include_hidden, max_files, on_progress):
            try:
                result = self._scan_single_file(file_path)
                if self._matches_filter(result, filter_criteria, filter_obj):
                    yield result
            except (OSError, ValueError) as e:
                logger.warning(f"Error scanning {file_path}: {e}")
                yield ScanResult(
                    path=str(file_path),
                    error=str(e),
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
        count = 0
        for result in self.scan(
            path,
            recursive=recursive,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
        ):
            if limit and count >= limit:
                break
            yield result
            count += 1

    def scan_tree(
        self,
        path: Union[str, Path],
        max_depth: Optional[int] = None,
    ) -> TreeNode:
        """
        Build a risk tree for directory visualization.

        Args:
            path: Root directory to scan
            max_depth: Maximum depth to recurse

        Returns:
            TreeNode representing the directory tree with risk data
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        return self._build_tree_node(path, current_depth=0, max_depth=max_depth)

    def _iter_files(
        self,
        path: Path,
        recursive: bool = True,
        include_hidden: bool = False,
        max_files: Optional[int] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Iterator[Path]:
        """Iterate over regular files in a directory. See SECURITY.md for TOCTOU-001."""
        walker = path.rglob("*") if recursive else path.glob("*")
        files_yielded = 0

        for file_path in walker:
            try:
                st = file_path.stat(follow_symlinks=False)  # TOCTOU-001
                # Skip non-regular files (directories, symlinks, devices, etc.)
                if not stat_module.S_ISREG(st.st_mode):
                    continue
            except OSError:
                # File doesn't exist, permission denied, or other issue - skip
                continue

            if not include_hidden and any(part.startswith('.') for part in file_path.parts):
                continue

            if max_files and files_yielded >= max_files:
                break

            if on_progress:
                on_progress(str(file_path))

            yield file_path
            files_yielded += 1

    def _scan_single_file(self, path: Path) -> ScanResult:
        """
        Scan a single file and return ScanResult.

        Detects if the file is modified during scanning by comparing
        quick hashes before and after detection.
        """
        from ..adapters.scanner import detect_file

        start_time = time.time()

        try:
            # Capture hash before detection to detect concurrent modification
            pre_hash = quick_hash(path)
            pre_stat = path.stat()

            detection_result = detect_file(path)
            entities = self._scorer._normalize_entity_counts(detection_result.entity_counts)
            confidence = self._scorer._calculate_average_confidence(detection_result.spans)

            scoring_result = score_entities(
                entities,
                exposure=self.default_exposure,
                confidence=confidence,
            )

            # Verify file unchanged after detection
            post_hash = quick_hash(path)
            post_stat = path.stat()

            # If either hash failed, skip modification check (file may be locked)
            if pre_hash is not None and post_hash is not None and pre_hash != post_hash:
                raise FileModifiedError(
                    f"File modified during scan: {path} "
                    f"(hash changed from {pre_hash[:8]}... to {post_hash[:8]}...)"
                )

            # Also check mtime as a secondary verification
            if pre_stat.st_mtime != post_stat.st_mtime:
                raise FileModifiedError(
                    f"File modified during scan: {path} (mtime changed)"
                )

            duration_ms = (time.time() - start_time) * 1000

            return ScanResult(
                path=str(path),
                size_bytes=post_stat.st_size,
                file_type=path.suffix.lower() or "unknown",
                score=scoring_result.score,
                tier=scoring_result.tier.value,
                scoring_result=scoring_result,
                entities=[],
                scan_duration_ms=duration_ms,
                scanned_at=datetime.utcnow().isoformat(),
                content_hash=post_hash,  # Include hash for downstream verification
            )

        except FileModifiedError as e:
            logger.warning(str(e))
            return ScanResult(
                path=str(path),
                error=str(e),
            )
        except (OSError, ValueError) as e:
            return ScanResult(
                path=str(path),
                error=str(e),
            )

    def _matches_filter(
        self,
        result: ScanResult,
        criteria: Optional[FilterCriteria],
        filter_obj: Optional[Filter],
    ) -> bool:
        """Check if a result matches filter criteria."""
        if result.error:
            return False

        if criteria:
            if criteria.min_score is not None:
                if result.score is None or result.score < criteria.min_score:
                    return False
            if criteria.max_score is not None:
                if result.score is None or result.score > criteria.max_score:
                    return False
            if criteria.tier:
                if result.tier is None or result.tier.upper() != criteria.tier.upper():
                    return False
            if criteria.path_pattern and not fnmatch.fnmatch(result.path, criteria.path_pattern):
                return False
            if criteria.file_type:
                if not result.file_type.lower().endswith(criteria.file_type.lower()):
                    return False
            if criteria.min_size is not None and result.size_bytes < criteria.min_size:
                return False
            if criteria.max_size is not None and result.size_bytes > criteria.max_size:
                return False

        if filter_obj:
            result_dict = result.to_dict()
            if not filter_obj.evaluate(result_dict):
                return False

        return True

    def _build_tree_node(
        self,
        path: Path,
        current_depth: int,
        max_depth: Optional[int],
    ) -> TreeNode:
        """Recursively build tree node. See SECURITY.md for TOCTOU-001."""
        name = path.name or str(path)

        try:
            st = path.stat(follow_symlinks=False)  # TOCTOU-001
            is_regular_file = stat_module.S_ISREG(st.st_mode)
            is_directory = stat_module.S_ISDIR(st.st_mode)
        except OSError:
            # Can't stat - treat as empty directory node
            return TreeNode(
                name=name,
                path=str(path),
                is_directory=True,
            )

        # Skip symlinks and special files
        if not is_regular_file and not is_directory:
            return TreeNode(
                name=name,
                path=str(path),
                is_directory=False,
                score=0,
                tier="MINIMAL",
            )

        if is_regular_file:
            result = self._scan_single_file(path)
            return TreeNode(
                name=name,
                path=str(path),
                is_directory=False,
                score=result.score if not result.error else 0,
                tier=result.tier if not result.error else "MINIMAL",
            )

        node = TreeNode(
            name=name,
            path=str(path),
            is_directory=True,
        )

        if max_depth is not None and current_depth >= max_depth:
            return node

        scores = []
        try:
            for child_path in path.iterdir():
                if child_path.name.startswith('.'):
                    continue

                child_node = self._build_tree_node(
                    child_path,
                    current_depth + 1,
                    max_depth,
                )
                node.children.append(child_node)

                if child_node.is_directory:
                    node.total_files += child_node.total_files
                    node.total_size += child_node.total_size
                    if child_node.max_score > 0:
                        scores.extend([child_node.avg_score] * child_node.total_files)
                    node.max_score = max(node.max_score, child_node.max_score)
                    for tier, count in child_node.score_distribution.items():
                        node.score_distribution[tier] = node.score_distribution.get(tier, 0) + count
                else:
                    node.total_files += 1
                    if child_node.score is not None:
                        scores.append(child_node.score)
                        node.max_score = max(node.max_score, child_node.score)
                        tier = child_node.tier or "MINIMAL"
                        node.score_distribution[tier] = node.score_distribution.get(tier, 0) + 1

        except PermissionError:
            logger.warning(f"Permission denied: {path}")

        if scores:
            node.avg_score = sum(scores) / len(scores)

        return node
