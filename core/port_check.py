"""Basic public port visibility checks using lightweight socket connects."""

from __future__ import annotations

import logging
import socket

LOGGER = logging.getLogger(__name__)

# Limited passive-style visibility check set (no aggressive scan behavior).
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443, 3306, 5432, 6379]


def check_public_ports(domain: str, timeout: float = 0.8) -> list[int]:
    """Check if selected common ports accept TCP connections."""
    open_ports: list[int] = []
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((domain, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            continue
    LOGGER.info("Detected %d publicly reachable ports for %s", len(open_ports), domain)
    return open_ports

