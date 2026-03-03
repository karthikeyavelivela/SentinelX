"""HTTP security headers inspection module."""

from __future__ import annotations

import logging
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)

RECOMMENDED_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def inspect_security_headers(domain: str, timeout: int = 10) -> dict[str, Any]:
    """Inspect publicly exposed HTTP response headers on HTTPS endpoint."""
    target = f"https://{domain}"
    output: dict[str, Any] = {"target_url": target, "present": {}, "missing": [], "error": None}

    try:
        response = requests.get(target, timeout=timeout, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header in RECOMMENDED_HEADERS:
            value = headers.get(header)
            if value:
                output["present"][header] = value
            else:
                output["missing"].append(header)
    except Exception as exc:
        LOGGER.warning("Header inspection failed for %s: %s", domain, exc)
        output["error"] = str(exc)
        output["missing"] = list(RECOMMENDED_HEADERS)

    return output

