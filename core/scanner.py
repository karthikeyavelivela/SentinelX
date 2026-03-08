"""Primary passive scanner orchestration for SentinelX — consulting-grade edition."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from core.dns_recon import collect_dns_records
from core.favicon_hash import fingerprint_favicon
from core.headers import inspect_security_headers
from core.port_check import check_public_ports
from core.ssl_analysis import analyze_ssl
from core.subdomain import enumerate_subdomains
from core.techstack import detect_tech_stack

LOGGER = logging.getLogger(__name__)

SCANNER_VERSION = "1.2.0"


def run_passive_scan(
    domain: str,
    analyst_name: str = "SentinelX Automated Engine",
    assessment_type: str = "External Passive Reconnaissance",
) -> dict[str, Any]:
    """Run all passive intelligence collectors and return structured scan data."""
    clean_domain = domain.strip().lower()
    LOGGER.info("Starting passive scan for %s", clean_domain)

    # Core collectors
    subdomains = enumerate_subdomains(clean_domain)
    ssl_summary = analyze_ssl(clean_domain)
    security_headers = inspect_security_headers(clean_domain)
    open_ports = check_public_ports(clean_domain)

    # Favicon fingerprinting (enhances tech stack detection)
    favicon_fp = fingerprint_favicon(clean_domain)
    LOGGER.info("Favicon fingerprint complete for %s", clean_domain)

    # Tech stack detection — informed by favicon hash
    tech_stack = detect_tech_stack(clean_domain, favicon_fingerprint=favicon_fp)

    # DNS reconnaissance
    dns_records = collect_dns_records(clean_domain)
    LOGGER.info("DNS reconnaissance complete for %s", clean_domain)

    return {
        "domain": clean_domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scanner_version": SCANNER_VERSION,
        "analyst_name": analyst_name,
        "assessment_type": assessment_type,
        "subdomains": subdomains,
        "ssl_summary": ssl_summary,
        "security_headers": security_headers,
        "tech_stack": tech_stack,
        "open_ports": open_ports,
        "dns_records": dns_records,
        "favicon_fingerprint": favicon_fp,
    }
