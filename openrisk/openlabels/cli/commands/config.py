"""
OpenLabels config command.

View and edit configuration.

Usage:
    openlabels config --show
    openlabels config --set scanning.threads 8
    openlabels config --reset
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any

from openlabels.cli.output import echo, error, success, config_tree, console
from openlabels.logging_config import get_logger

logger = get_logger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "scanning": {
        "max_file_size_mb": 100,
        "threads": 4,
        "include_archives": False,
        "excluded_patterns": [".git", "node_modules", "__pycache__"],
    },
    "storage": {
        "quarantine_path": str(Path.home() / ".openlabels" / "quarantine"),
        "index_backend": "sqlite",
        "label_storage": "xattr",
    },
    "display": {
        "show_hidden_files": False,
        "max_results": 100,
    },
}


def get_config_path() -> Path:
    """Get the configuration file path."""
    return Path.home() / ".openlabels" / "config.json"


def load_config() -> Dict[str, Any]:
    """Load configuration from file."""
    config_path = get_config_path()

    if not config_path.exists():
        return DEFAULT_CONFIG.copy()

    try:
        with open(config_path) as f:
            loaded = json.load(f)
            # Merge with defaults
            config = DEFAULT_CONFIG.copy()
            deep_merge(config, loaded)
            return config
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load config: {e}")
        return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any]) -> bool:
    """Save configuration to file."""
    config_path = get_config_path()

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except IOError as e:
        logger.error(f"Failed to save config: {e}")
        return False


def deep_merge(base: Dict, override: Dict) -> None:
    """Deep merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value


def get_nested_value(config: Dict, key_path: str) -> Any:
    """Get a nested value using dot notation (e.g., 'scanning.threads')."""
    keys = key_path.split(".")
    value = config
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


def set_nested_value(config: Dict, key_path: str, value: Any) -> bool:
    """Set a nested value using dot notation."""
    keys = key_path.split(".")
    target = config

    for key in keys[:-1]:
        if key not in target:
            target[key] = {}
        target = target[key]

    final_key = keys[-1]

    # Type conversion based on existing value
    existing = target.get(final_key)
    if existing is not None:
        if isinstance(existing, bool):
            value = value.lower() in ("true", "1", "yes", "on")
        elif isinstance(existing, int):
            try:
                value = int(value)
            except ValueError:
                return False
        elif isinstance(existing, float):
            try:
                value = float(value)
            except ValueError:
                return False
        elif isinstance(existing, list):
            value = [v.strip() for v in value.split(",")]

    target[final_key] = value
    return True


def cmd_config(args) -> int:
    """Execute the config command."""
    config = load_config()

    # Show configuration
    if args.show:
        config_tree(config, title="OpenLabels Configuration")
        echo("")
        echo(f"Config file: {get_config_path()}")
        return 0

    # Get a specific value
    if args.get:
        value = get_nested_value(config, args.get)
        if value is None:
            error(f"Unknown config key: {args.get}")
            return 1
        echo(f"{args.get}: {value}")
        return 0

    # Set a value
    if args.set:
        if len(args.set) != 2:
            error("Usage: --set <key> <value>")
            return 1

        key, value = args.set
        if not set_nested_value(config, key, value):
            error(f"Failed to set {key}")
            return 1

        if save_config(config):
            success(f"Set {key} = {get_nested_value(config, key)}")
            return 0
        else:
            error("Failed to save configuration")
            return 1

    # Reset to defaults
    if args.reset:
        if save_config(DEFAULT_CONFIG):
            success("Configuration reset to defaults")
            return 0
        else:
            error("Failed to reset configuration")
            return 1

    # Default: show config
    config_tree(config, title="OpenLabels Configuration")
    echo("")
    echo(f"Config file: {get_config_path()}")
    echo("")
    echo("Commands:")
    echo("  openlabels config --show              Show configuration")
    echo("  openlabels config --get <key>         Get a value")
    echo("  openlabels config --set <key> <value> Set a value")
    echo("  openlabels config --reset             Reset to defaults")

    return 0


def add_config_parser(subparsers, hidden=False):
    """Add the config subparser."""
    import argparse
    parser = subparsers.add_parser(
        "config",
        help=argparse.SUPPRESS if hidden else "View and edit configuration",
    )
    parser.add_argument(
        "--show", "-s",
        action="store_true",
        help="Show current configuration",
    )
    parser.add_argument(
        "--get", "-g",
        metavar="KEY",
        help="Get a configuration value (e.g., scanning.threads)",
    )
    parser.add_argument(
        "--set",
        nargs=2,
        metavar=("KEY", "VALUE"),
        help="Set a configuration value",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset configuration to defaults",
    )
    parser.set_defaults(func=cmd_config)

    return parser
