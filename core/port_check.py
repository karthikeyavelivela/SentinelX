"""Basic public port visibility checks using lightweight socket connects."""

from __future__ import annotations

import logging
import socket
import time

LOGGER = logging.getLogger(__name__)


def probe_exposed_ports(
    domain: str,
    *,
    ports: list[int] | None = None,
    timeout: float = 3.0,
    rate_limit_ms: int = 0,
    max_retries: int = 0,
) -> list[int]:
    """Perform lightweight TCP socket probing against configured ports."""
    open_ports: list[int] = []
    target_ports = ports or []

    for port in target_ports:
        for attempt in range(max(max_retries, 0) + 1):
            try:
                with socket.create_connection((domain, port), timeout=timeout):
                    open_ports.append(port)
                    break
            except Exception:
                if attempt == max(max_retries, 0):
                    break
            finally:
                if rate_limit_ms > 0:
                    time.sleep(rate_limit_ms / 1000)

    LOGGER.info("Detected %d publicly reachable ports for %s", len(open_ports), domain)
    return open_ports
