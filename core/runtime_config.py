"""Runtime configuration loading for SentinelX."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "timeouts": {
        "http": 10,
        "dns": 5,
        "tcp": 3,
    },
    "ports": [21, 22, 23, 25, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 9200, 11211],
    "user_agent": "SentinelX/2.0 Security Audit Scanner",
    "subdomain_sources": ["crtsh", "hackertarget"],
    "rate_limit_ms": 300,
    "max_retries": 2,
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_runtime_config(config_path: str | None = None) -> tuple[dict[str, Any], str]:
    """Load YAML configuration and merge it with the default profile."""
    resolved_path = Path(config_path or "config.yaml").resolve()
    if not resolved_path.exists():
        return deepcopy(DEFAULT_CONFIG), str(resolved_path)

    with resolved_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    if not isinstance(raw, dict):
        raise ValueError(f"Invalid config format in {resolved_path}: top-level YAML must be a mapping.")

    config = _deep_merge(DEFAULT_CONFIG, raw)
    return config, str(resolved_path)
