"""HTTP helper utilities shared by SentinelX collectors."""

from __future__ import annotations

import logging
import time

import requests

LOGGER = logging.getLogger(__name__)


def rate_limit_sleep(rate_limit_ms: int) -> None:
    if rate_limit_ms > 0:
        time.sleep(rate_limit_ms / 1000)


def get_with_retries(
    url: str,
    *,
    timeout: int,
    headers: dict[str, str] | None = None,
    allow_redirects: bool = True,
    rate_limit_ms: int = 0,
    max_retries: int = 0,
) -> requests.Response:
    """Execute a GET with bounded retry behavior."""
    last_exc: Exception | None = None
    attempts = max(max_retries, 0) + 1
    for attempt in range(attempts):
        rate_limit_sleep(rate_limit_ms)
        try:
            return requests.get(
                url,
                timeout=timeout,
                headers=headers,
                allow_redirects=allow_redirects,
            )
        except requests.RequestException as exc:
            last_exc = exc
            if attempt == attempts - 1:
                break
            LOGGER.debug("Retrying GET %s after error: %s", url, exc)
    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"GET request failed without exception for {url}")
