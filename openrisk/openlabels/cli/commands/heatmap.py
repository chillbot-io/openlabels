"""
OpenLabels heatmap command.

Display a visual risk heatmap of directory structure.

Usage:
    openlabels heatmap <path>
    openlabels heatmap ./data --depth 3
"""

import stat as stat_module
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from openlabels import Client
from openlabels.cli.commands.scan import scan_file, ScanResult
from openlabels.cli.output import echo, error, info, progress, console
from openlabels.logging_config import get_logger
from openlabels.core.scorer import TIER_THRESHOLDS

logger = get_logger(__name__)


@dataclass
class TreeNode:
    """A node in the directory tree."""
    name: str
    path: Path
    is_dir: bool
    score: int = 0
    tier: str = ""
    children: List["TreeNode"] = field(default_factory=list)
    entity_counts: Dict[str, int] = field(default_factory=dict)
    file_count: int = 0
    error: Optional[str] = None

    @property
    def avg_score(self) -> float:
        """Calculate average score including children."""
        if not self.is_dir:
            return float(self.score)

        if not self.children:
            return 0.0

        total = sum(c.avg_score for c in self.children)
        return total / len(self.children) if self.children else 0.0

    @property
    def max_score(self) -> int:
        """Get maximum score including children."""
        if not self.is_dir:
            return self.score

        if not self.children:
            return 0

        return max(c.max_score for c in self.children)


def build_tree(
    path: Path,
    client: Client,
    depth: int = 3,
    current_depth: int = 0,
    exposure: str = "PRIVATE",
    extensions: Optional[List[str]] = None,
) -> TreeNode:
    """Build a tree structure with risk scores."""
    try:
        st = path.lstat()  # TOCTOU-001: atomic stat
        is_regular_file = stat_module.S_ISREG(st.st_mode)
        is_directory = stat_module.S_ISDIR(st.st_mode)
    except OSError:
        return TreeNode(name=path.name or str(path), path=path, is_dir=True, error="Cannot access")

    node = TreeNode(
        name=path.name or str(path),
        path=path,
        is_dir=is_directory,
    )

    if is_regular_file:
        # Scan file using scan_file for proper entity tracking
        scan_result = scan_file(path, client, exposure)
        node.score = scan_result.score
        node.tier = scan_result.tier
        node.entity_counts = scan_result.entities
        node.file_count = 1
        node.error = scan_result.error
        return node

    if current_depth >= depth:
        # At max depth, scan all files in this directory recursively
        total_score = 0
        file_count = 0
        all_entities: Dict[str, int] = {}

        for file_path in path.rglob("*"):
            try:
                child_st = file_path.lstat()  # TOCTOU-001
                if not stat_module.S_ISREG(child_st.st_mode):
                    continue
            except OSError as e:
                # Log file access errors at DEBUG level
                logger.debug(f"Could not stat file in heatmap scan: {file_path}: {e}")
                continue

            if extensions:
                if file_path.suffix.lower().lstrip(".") not in extensions:
                    continue

            scan_result = scan_file(file_path, client, exposure)
            total_score += scan_result.score
            file_count += 1

            for etype, count in scan_result.entities.items():
                all_entities[etype] = all_entities.get(etype, 0) + count

        node.score = total_score // file_count if file_count else 0
        node.file_count = file_count
        node.entity_counts = all_entities
        return node

    # Recurse into children
    try:
        def sort_key(p):  # TOCTOU-001: use lstat
            try:
                s = p.lstat()
                return (not stat_module.S_ISDIR(s.st_mode), p.name.lower())
            except OSError as e:
                logger.debug(f"Could not stat path during sort: {p}: {e}")
                return (True, p.name.lower())
        children = sorted(path.iterdir(), key=sort_key)
    except PermissionError:
        node.error = "Permission denied"
        return node

    for child_path in children:
        # Skip hidden files/dirs
        if child_path.name.startswith("."):
            continue

        try:
            child_st = child_path.lstat()  # TOCTOU-001
            child_is_file = stat_module.S_ISREG(child_st.st_mode)
        except OSError as e:
            logger.debug(f"Could not stat child path in heatmap: {child_path}: {e}")
            continue

        if child_is_file:
            if extensions:
                if child_path.suffix.lower().lstrip(".") not in extensions:
                    continue

        child_node = build_tree(
            child_path,
            client,
            depth=depth,
            current_depth=current_depth + 1,
            exposure=exposure,
            extensions=extensions,
        )
        node.children.append(child_node)

    # Aggregate stats
    node.file_count = sum(c.file_count for c in node.children)
    for child in node.children:
        for etype, count in child.entity_counts.items():
            node.entity_counts[etype] = node.entity_counts.get(etype, 0) + count

    return node


def score_to_bar(score: float, width: int = 20) -> str:
    """Convert score to a visual bar."""
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def score_to_indicator(score: float) -> str:
    """Get color indicator for score using actual tier thresholds."""
    if score >= TIER_THRESHOLDS['critical']:
        return "🔴"  # Critical
    elif score >= TIER_THRESHOLDS['high']:
        return "🟠"  # High
    elif score >= TIER_THRESHOLDS['medium']:
        return "🟡"  # Medium
    elif score >= TIER_THRESHOLDS['low']:
        return "🟢"  # Low
    else:
        return "⚪"  # Minimal


def score_to_rich_color(score: float) -> str:
    """Get rich color style for score using actual tier thresholds."""
    if score >= TIER_THRESHOLDS['critical']:
        return "bold red"
    elif score >= TIER_THRESHOLDS['high']:
        return "yellow"
    elif score >= TIER_THRESHOLDS['medium']:
        return "orange3"
    elif score >= TIER_THRESHOLDS['low']:
        return "green"
    else:
        return "dim"


def render_tree_rich(
    node: TreeNode,
    indent: int = 0,
    prefix: str = "",
    is_last: bool = True,
    show_entities: bool = False,
) -> None:
    """Render a tree node using rich formatting."""
    # Build the tree branch characters
    if indent == 0:
        branch = ""
    else:
        branch = prefix + ("└── " if is_last else "├── ")

    # Get score info
    if node.is_dir:
        avg = node.avg_score
        max_s = node.max_score
        color = score_to_rich_color(max_s)
        indicator = score_to_indicator(max_s)
        bar = score_to_bar(avg)
        score_str = f"{bar} avg:{avg:>5.1f} max:{max_s:>3}"
        icon = "📁"
        name = f"{node.name}/" if node.name else str(node.path)
        files_str = f"({node.file_count} files)"
    else:
        color = score_to_rich_color(node.score)
        indicator = score_to_indicator(node.score)
        bar = score_to_bar(node.score)
        score_str = f"{bar} {node.score:>3}"
        icon = "📄"
        name = node.name
        files_str = ""

    # Error handling
    if node.error:
        console.print(f"{branch}{icon} {name} [red]\\[ERROR: {node.error}][/red]")
    else:
        console.print(
            f"{branch}{icon} {name:<40} [{color}]{score_str}[/{color}] {indicator} {files_str}"
        )

        # Show entities if requested
        if show_entities and node.entity_counts:
            entities = ", ".join(f"{k}({v})" for k, v in sorted(node.entity_counts.items()))
            entity_prefix = prefix + ("    " if is_last else "│   ") if indent > 0 else ""
            console.print(f"{entity_prefix}    └─ [dim]{entities}[/dim]")

    # Render children
    if node.children:
        child_prefix = prefix + ("    " if is_last else "│   ") if indent > 0 else ""

        for i, child in enumerate(node.children):
            child_is_last = (i == len(node.children) - 1)
            render_tree_rich(
                child,
                indent=indent + 1,
                prefix=child_prefix,
                is_last=child_is_last,
                show_entities=show_entities,
            )


def cmd_heatmap(args) -> int:
    """Execute the heatmap command."""
    path = Path(args.path)

    if not path.exists():
        error(f"Path not found: {path}")
        return 1

    logger.info(f"Starting heatmap", extra={
        "path": str(path),
        "depth": args.depth,
    })

    client = Client(default_exposure=args.exposure)
    extensions = args.extensions.split(",") if args.extensions else None

    info(f"Building risk heatmap for {path}...")
    echo("")

    # Build tree
    tree = build_tree(
        path,
        client,
        depth=args.depth,
        exposure=args.exposure,
        extensions=extensions,
    )

    # Render using rich
    render_tree_rich(
        tree,
        show_entities=args.show_entities,
    )

    # Print legend with actual tier thresholds
    crit = TIER_THRESHOLDS['critical']
    high = TIER_THRESHOLDS['high']
    med = TIER_THRESHOLDS['medium']
    low = TIER_THRESHOLDS['low']
    echo("")
    echo(f"Legend: 🔴 Critical({crit}+) 🟠 High({high}-{crit-1}) 🟡 Medium({med}-{high-1}) 🟢 Low({low}-{med-1}) ⚪ Minimal(<{low})")

    # Print summary
    echo("")
    echo(f"Total files: {tree.file_count}")
    echo(f"Max score: {tree.max_score}")
    echo(f"Avg score: {tree.avg_score:.1f}")

    if tree.entity_counts:
        top_entities = sorted(tree.entity_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        entities_str = ", ".join(f"{k}({v})" for k, v in top_entities)
        echo(f"Top entities: {entities_str}")

    logger.info(f"Heatmap complete", extra={
        "total_files": tree.file_count,
        "max_score": tree.max_score,
    })

    return 0


def add_heatmap_parser(subparsers, hidden=False):
    """Add the heatmap subparser."""
    import argparse
    parser = subparsers.add_parser(
        "heatmap",
        help=argparse.SUPPRESS if hidden else "Display risk heatmap of directory structure",
    )
    parser.add_argument(
        "path",
        help="Path to visualize",
    )
    parser.add_argument(
        "--depth", "-d",
        type=int,
        default=3,
        help="Maximum directory depth to display (default: 3)",
    )
    parser.add_argument(
        "--exposure", "-e",
        choices=["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"],
        default="PRIVATE",
        help="Exposure level for scoring",
    )
    parser.add_argument(
        "--extensions",
        help="Comma-separated list of file extensions",
    )
    parser.add_argument(
        "--show-entities", "-s",
        action="store_true",
        help="Show entity types for each item",
    )
    parser.set_defaults(func=cmd_heatmap)

    return parser
