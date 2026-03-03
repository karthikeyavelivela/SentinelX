"""Structured output formatter, Exposure Score engine, and risk classification."""

from __future__ import annotations

import json
import logging
from typing import Any

LOGGER = logging.getLogger(__name__)

COMMON_WEB_PORTS: set[int] = {80, 443, 8080, 8443}
SENSITIVE_PORTS: set[int] = {21, 22, 23, 25, 3306, 3389, 5432, 5900, 6379, 27017}

STAGING_KEYWORDS = ("staging", "stage", "dev", "test", "uat", "preprod")
HIGH_RISK_PATTERNS = (
    "dev", "staging", "test", "beta", "admin", "api", "internal",
    "preprod", "uat", "mgmt", "management", "staff", "secret",
)

CRITICAL_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
)


# ---------------------------------------------------------------------------
# Exposure Score Engine
# ---------------------------------------------------------------------------

def compute_exposure_score(
    ssl_summary: dict[str, Any],
    subdomains: list[str],
    open_ports: list[int],
    missing_headers: list[str],
) -> tuple[int, str]:
    """Compute a 1-10 Exposure Score and return (score, level)."""
    score = 1

    if ssl_summary.get("expired") is True:
        score += 2

    pattern_hosts = _flag_pattern_subdomains(subdomains)
    if pattern_hosts:
        score += 2

    sensitive_open = [p for p in open_ports if p in SENSITIVE_PORTS]
    if sensitive_open:
        score += 2

    missing_lower = [h.lower() for h in missing_headers]
    for header in CRITICAL_HEADERS:
        if header in missing_lower:
            score += 1

    if len(subdomains) > 5:
        score += 1

    score = min(score, 10)

    if score <= 3:
        level = "Low"
    elif score <= 7:
        level = "Medium"
    else:
        level = "High"

    return score, level


# ---------------------------------------------------------------------------
# Pattern Subdomain Detection
# ---------------------------------------------------------------------------

def _flag_pattern_subdomains(subdomains: list[str]) -> list[str]:
    """Return subdomains matching high-risk naming patterns."""
    flagged: list[str] = []
    for host in subdomains:
        labels = host.lower().split(".")
        if any(label in HIGH_RISK_PATTERNS for label in labels):
            flagged.append(host)
    return flagged


# ---------------------------------------------------------------------------
# Attack Surface Summary
# ---------------------------------------------------------------------------

def build_attack_surface(
    subdomains: list[str],
    ssl_summary: dict[str, Any],
    security_headers: dict[str, Any],
    open_ports: list[int],
    tech_stack: list[str],
) -> dict[str, Any]:
    """Build the structured Attack Surface Overview block."""
    missing_headers: list[str] = security_headers.get("missing", [])
    critical_missing = [
        h for h in missing_headers if h.lower() in CRITICAL_HEADERS
    ]
    pattern_hosts = _flag_pattern_subdomains(subdomains)
    sensitive_open = [p for p in open_ports if p in SENSITIVE_PORTS]

    tls_status: str
    if not ssl_summary.get("reachable"):
        tls_status = "Unreachable"
    elif ssl_summary.get("expired"):
        tls_status = "Expired"
    elif ssl_summary.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3"):
        tls_status = "Weak"
    else:
        tls_status = "Valid"

    return {
        "total_subdomains": len(subdomains),
        "high_risk_subdomains": pattern_hosts,
        "tls_status": tls_status,
        "missing_critical_headers": critical_missing,
        "sensitive_open_ports": sensitive_open,
        "tech_stack_summary": tech_stack,
    }


# ---------------------------------------------------------------------------
# Preliminary Risk Buckets
# ---------------------------------------------------------------------------

def build_risk_preliminary(scan_data: dict[str, Any]) -> dict[str, list[str]]:
    """Create contextual risk buckets enriched with business language."""
    high: list[str] = []
    medium: list[str] = []
    low: list[str] = []

    ssl_summary = scan_data.get("ssl_summary", {})
    security_headers = scan_data.get("security_headers", {})
    subdomains = scan_data.get("subdomains", [])
    open_ports = scan_data.get("open_ports", [])
    tech_stack = scan_data.get("tech_stack", [])

    if ssl_summary.get("expired") is True:
        high.append(
            "Expired SSL/TLS certificate — HTTPS connections will display browser security warnings, "
            "eroding user trust and enabling potential interception."
        )

    sensitive_open = [p for p in open_ports if p in SENSITIVE_PORTS]
    if sensitive_open:
        port_list = ", ".join(str(p) for p in sensitive_open)
        high.append(
            f"Sensitive service ports publicly reachable ({port_list}) — direct attack surface for "
            "credential brute-force, vulnerability exploitation, and lateral movement."
        )

    missing: list[str] = security_headers.get("missing", [])
    missing_lower = [h.lower() for h in missing]

    if "strict-transport-security" in missing_lower:
        medium.append(
            "HSTS header absent — browsers may permit unencrypted HTTP connections, exposing "
            "session tokens to network-level interception."
        )
    if "content-security-policy" in missing_lower:
        medium.append(
            "Content-Security-Policy header absent — application is unprotected against cross-site "
            "scripting (XSS) and content-injection attacks."
        )
    if "x-frame-options" in missing_lower:
        medium.append(
            "X-Frame-Options header absent — application may be embeddable in third-party frames, "
            "enabling clickjacking attacks against authenticated users."
        )

    pattern_hosts = _flag_pattern_subdomains(subdomains)
    if pattern_hosts:
        host_list = ", ".join(pattern_hosts[:5])
        ellipsis = f" (+{len(pattern_hosts) - 5} more)" if len(pattern_hosts) > 5 else ""
        medium.append(
            f"High-risk pattern subdomains publicly reachable: {host_list}{ellipsis} — these hosts "
            "commonly expose pre-production builds, administrative panels, or internal APIs "
            "with weaker security controls."
        )

    uncommon = [p for p in open_ports if p not in COMMON_WEB_PORTS and p not in SENSITIVE_PORTS]
    if uncommon:
        port_list = ", ".join(str(p) for p in uncommon)
        medium.append(
            f"Non-standard ports publicly reachable ({port_list}) — service identification and "
            "version-probing by external parties is feasible via passive observation."
        )

    if ssl_summary.get("reachable") is True and not ssl_summary.get("expired"):
        low.append("Valid TLS endpoint reachable. Certificate chain and expiry details collected.")
    if tech_stack:
        low.append(
            f"Technology stack fingerprinted ({len(tech_stack)} indicators). "
            "Public exposure of framework and version information may inform targeted research."
        )
    if len(subdomains) > 5:
        low.append(
            f"{len(subdomains)} resolvable subdomains discovered. Broad subdomain exposure increases "
            "overall attack surface and enumeration potential."
        )
    if not medium and not high:
        low.append(
            "No immediate high-confidence risk indicators identified from passive observation. "
            "Continued monitoring is recommended."
        )

    return {"high": high, "medium": medium, "low": low}


# ---------------------------------------------------------------------------
# Main Output Builder
# ---------------------------------------------------------------------------

def build_structured_output(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Build the complete structured JSON payload with Exposure Score."""
    subdomains: list[str] = scan_data.get("subdomains", [])
    ssl_summary: dict[str, Any] = scan_data.get("ssl_summary", {})
    security_headers: dict[str, Any] = scan_data.get("security_headers", {})
    open_ports: list[int] = scan_data.get("open_ports", [])
    tech_stack: list[str] = scan_data.get("tech_stack", [])

    missing_headers: list[str] = security_headers.get("missing", [])
    attack_surface = build_attack_surface(
        subdomains, ssl_summary, security_headers, open_ports, tech_stack
    )
    exposure_score, exposure_level = compute_exposure_score(
        ssl_summary, subdomains, open_ports, missing_headers
    )
    risk_preliminary = build_risk_preliminary(scan_data)

    return {
        "domain": scan_data.get("domain"),
        "timestamp": scan_data.get("timestamp"),
        "subdomains": subdomains,
        "ssl_summary": ssl_summary,
        "security_headers": security_headers,
        "tech_stack": tech_stack,
        "open_ports": open_ports,
        "attack_surface": attack_surface,
        "exposure_score": exposure_score,
        "exposure_level": exposure_level,
        "risk_preliminary": risk_preliminary,
    }


def save_json(data: dict[str, Any], path: str) -> None:
    """Write JSON to disk with stable formatting."""
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
    LOGGER.info("Saved JSON output to %s", path)
