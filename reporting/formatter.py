"""Structured output formatter and preliminary risk classification."""

from __future__ import annotations

import json
from typing import Any

COMMON_WEB_PORTS = {80, 443, 8080, 8443}
STAGING_KEYWORDS = ("staging", "stage", "dev", "test", "uat", "preprod")


def build_risk_preliminary(scan_data: dict[str, Any]) -> dict[str, list[str]]:
    """Create lightweight preliminary risk buckets from passive findings."""
    high: list[str] = []
    medium: list[str] = []
    low: list[str] = []

    ssl_summary = scan_data.get("ssl_summary", {})
    security_headers = scan_data.get("security_headers", {})
    subdomains = scan_data.get("subdomains", [])
    open_ports = scan_data.get("open_ports", [])
    tech_stack = scan_data.get("tech_stack", [])

    if ssl_summary.get("expired") is True:
        high.append("SSL/TLS certificate appears expired.")

    missing = set(security_headers.get("missing", []))
    if "strict-transport-security" in missing:
        medium.append("HSTS header is missing.")

    staging_hosts = [s for s in subdomains if any(word in s for word in STAGING_KEYWORDS)]
    if staging_hosts:
        medium.append(f"Potential staging/test subdomain exposure: {', '.join(staging_hosts)}")

    uncommon = [p for p in open_ports if p not in COMMON_WEB_PORTS]
    if uncommon:
        medium.append(f"Uncommon publicly reachable ports detected: {', '.join(map(str, uncommon))}")

    if ssl_summary.get("reachable") is True:
        low.append("TLS endpoint is reachable and certificate details were collected.")
    if tech_stack:
        low.append(f"Technology fingerprinting identified {len(tech_stack)} indicators.")
    if not medium and not high:
        low.append("No immediate high-confidence risk flags identified from passive checks.")

    return {"high": high, "medium": medium, "low": low}


def build_structured_output(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Build the expected structured JSON payload shape."""
    return {
        "domain": scan_data.get("domain"),
        "timestamp": scan_data.get("timestamp"),
        "subdomains": scan_data.get("subdomains", []),
        "ssl_summary": scan_data.get("ssl_summary", {}),
        "security_headers": scan_data.get("security_headers", {}),
        "tech_stack": scan_data.get("tech_stack", []),
        "open_ports": scan_data.get("open_ports", []),
        "risk_preliminary": build_risk_preliminary(scan_data),
    }


def save_json(data: dict[str, Any], path: str) -> None:
    """Write JSON to disk with stable formatting."""
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

