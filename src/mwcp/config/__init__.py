"""Stores default configuration values."""

import logging
from pathlib import Path

import platformdirs
from dynaconf import Dynaconf, Validator


user_config_dir = platformdirs.user_config_path("mwcp", appauthor="dc3")

default_config = Path(__file__).parent / "settings.toml"
user_config = user_config_dir / "settings.toml"
legacy_config = platformdirs.user_config_path("mwcp") / "config.yml"
local_config = Path("mwcp.toml")

log_config = Path(__file__).parent / "log_config.yml"

report_formats = ["csv", "json", "simple", "markdown", "html", "stix"]


settings = Dynaconf(
    envvar_prefix="MWCP",
    load_dotenv=True,
    merge_enabled=True,
    settings_file=[
        default_config,
        legacy_config,
        user_config,
        local_config,
    ],
    validators=[
        Validator(
            "REPORT__FORMAT",
            cast=lambda v: v.lower(),
            is_in=report_formats,
            messages={
                "operations": "'{value}' for {name} is invalid. Must be one of: {op_value}",
            }
        ),
    ],
    # Defaults
    log_config_path=str(log_config),
    pytest_cache_dir=str(user_config_dir / ".pytest_cache"),
)
