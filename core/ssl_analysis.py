"""SSL/TLS metadata collection for passive exposure intelligence."""

from __future__ import annotations

import datetime as dt
import logging
import socket
import ssl
from typing import Any

LOGGER = logging.getLogger(__name__)


def analyze_ssl(domain: str, timeout: int = 6) -> dict[str, Any]:
    """Collect certificate and TLS details from port 443 without intrusive activity."""
    result: dict[str, Any] = {
        "reachable": False,
        "expired": None,
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "issuer": None,
        "subject": None,
        "tls_version": None,
        "cipher": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                result["reachable"] = True
                result["tls_version"] = tls_sock.version()
                cipher = tls_sock.cipher()
                result["cipher"] = cipher[0] if cipher else None

                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                result["valid_from"] = not_before
                result["valid_to"] = not_after
                result["issuer"] = cert.get("issuer")
                result["subject"] = cert.get("subject")

                if not_after:
                    expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
                    delta = expiry - now
                    result["days_remaining"] = delta.days
                    result["expired"] = delta.total_seconds() < 0
                else:
                    result["expired"] = None
    except Exception as exc:
        LOGGER.warning("SSL analysis failed for %s: %s", domain, exc)
        result["error"] = str(exc)

    return result

