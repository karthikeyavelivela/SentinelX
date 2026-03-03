"""Primary passive scanner orchestration for SentinelX."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from core.headers import inspect_security_headers
from core.port_check import check_public_ports
from core.ssl_analysis import analyze_ssl
from core.subdomain import enumerate_subdomains
from core.techstack import detect_tech_stack

LOGGER = logging.getLogger(__name__)


def run_passive_scan(domain: str) -> dict[str, Any]:
    """Run all passive intelligence collectors and return structured scan data."""
    clean_domain = domain.strip().lower()
    LOGGER.info("Starting passive scan for %s", clean_domain)

    subdomains = enumerate_subdomains(clean_domain)
    ssl_summary = analyze_ssl(clean_domain)
    security_headers = inspect_security_headers(clean_domain)
    tech_stack = detect_tech_stack(clean_domain)
    open_ports = check_public_ports(clean_domain)

    return {
        "domain": clean_domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subdomains": subdomains,
        "ssl_summary": ssl_summary,
        "security_headers": security_headers,
        "tech_stack": tech_stack,
        "open_ports": open_ports,
    }

