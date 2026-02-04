"""
Configuration management commands.
"""

import click


@click.group()
def config():
    """Configuration management."""
    pass


@config.command("show")
def config_show():
    """Display current configuration."""
    from openlabels.server.config import get_settings

    settings = get_settings()
    click.echo(settings.model_dump_json(indent=2))


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    """
    Set a configuration value.

    KEY is a dot-separated path like 'server.port' or 'cors.allowed_origins'.
    VALUE is the value to set. For lists, use comma-separated values.

    Examples:
        openlabels config set server.port 9000
        openlabels config set server.debug true
        openlabels config set cors.allowed_origins http://localhost:3000,http://example.com
    """
    import yaml
    from pathlib import Path
    from openlabels.core.constants import DATA_DIR

    # Determine config file location
    config_paths = [
        Path("config.yaml"),
        Path("config/config.yaml"),
        DATA_DIR / "config.yaml",
    ]

    config_path = None
    for p in config_paths:
        if p.exists():
            config_path = p
            break

    # Default to first path if none exist
    if config_path is None:
        config_path = config_paths[0]

    # Load existing config
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    else:
        config = {}
        # Create parent directories if needed
        config_path.parent.mkdir(parents=True, exist_ok=True)

    # Parse the key path
    keys = key.split(".")
    current = config

    # Navigate/create nested structure
    for k in keys[:-1]:
        if k not in current:
            current[k] = {}
        elif not isinstance(current[k], dict):
            click.echo(f"Error: Cannot set nested key under non-dict value at '{k}'", err=True)
            return
        current = current[k]

    # Convert value to appropriate type
    final_key = keys[-1]
    converted_value: any

    # Handle booleans
    if value.lower() in ("true", "yes", "on", "1"):
        converted_value = True
    elif value.lower() in ("false", "no", "off", "0"):
        converted_value = False
    # Handle integers
    elif value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        converted_value = int(value)
    # Handle floats
    elif value.replace(".", "", 1).replace("-", "", 1).isdigit():
        converted_value = float(value)
    # Handle lists (comma-separated)
    elif "," in value:
        converted_value = [v.strip() for v in value.split(",")]
    # Handle null
    elif value.lower() in ("null", "none", "~"):
        converted_value = None
    else:
        converted_value = value

    # Set the value
    current[final_key] = converted_value

    # Write config back
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    click.echo(f"Set {key} = {converted_value}")
    click.echo(f"Config saved to: {config_path}")
    click.echo("Note: Server restart required for changes to take effect")
