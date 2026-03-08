"""Structured output formatter, Exposure Score engine, risk classification, OWASP mapping."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

LOGGER = logging.getLogger(__name__)

SCANNER_VERSION = "1.2.0"

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
# OWASP Top 10 (2021) Mapping
# ---------------------------------------------------------------------------

OWASP_CATEGORIES: dict[str, str] = {
    "A01": "A01:2021 – Broken Access Control",
    "A02": "A02:2021 – Cryptographic Failures",
    "A03": "A03:2021 – Injection",
    "A04": "A04:2021 – Insecure Design",
    "A05": "A05:2021 – Security Misconfiguration",
    "A06": "A06:2021 – Vulnerable and Outdated Components",
    "A07": "A07:2021 – Identification and Authentication Failures",
    "A08": "A08:2021 – Software and Data Integrity Failures",
    "A09": "A09:2021 – Security Logging and Monitoring Failures",
    "A10": "A10:2021 – Server-Side Request Forgery (SSRF)",
}

# Finding keyword → OWASP category mapping
FINDING_OWASP_MAP: list[tuple[str, str, str]] = [
    # (keyword_in_finding, owasp_code, brief_rationale)
    ("ssl", "A02", "Cryptographic failure — weak/expired TLS exposes data in transit"),
    ("tls", "A02", "Cryptographic failure — outdated TLS protocol enables downgrade attacks"),
    ("certificate", "A02", "Certificate misconfiguration undermines transport-layer trust"),
    ("hsts", "A02", "Missing HSTS enables protocol downgrade, exposing encrypted sessions"),
    ("content-security-policy", "A05", "Absent CSP constitutes security misconfiguration enabling XSS"),
    ("csp", "A05", "Missing Content-Security-Policy — security misconfiguration"),
    ("x-frame-options", "A05", "Missing framing protection — clickjacking via misconfiguration"),
    ("x-content-type", "A05", "Missing MIME-type protection — security misconfiguration"),
    ("referrer-policy", "A05", "Missing referrer policy — information leakage misconfiguration"),
    ("permissions-policy", "A05", "Uncontrolled browser feature access — security misconfiguration"),
    ("port 21", "A05", "Publicly exposed FTP — misconfigured network attack surface"),
    ("port 22", "A05", "Publicly exposed SSH — misconfigured network attack surface"),
    ("port 3389", "A05", "Publicly exposed RDP — critical misconfiguration"),
    ("port 3306", "A05", "Publicly exposed database — security misconfiguration"),
    ("ftp", "A05", "FTP protocol exposure — security misconfiguration"),
    ("rdp", "A05", "Remote Desktop Protocol exposure — security misconfiguration"),
    ("mysql", "A05", "Database service publicly exposed — security misconfiguration"),
    ("redis", "A05", "Redis exposed publicly — misconfigured data store"),
    ("mongodb", "A05", "MongoDB exposed publicly — misconfigured data store"),
    ("elasticsearch", "A05", "Elasticsearch exposed publicly — misconfigured search engine"),
    ("staging", "A04", "Pre-production environment exposed — insecure design"),
    ("dev", "A04", "Development environment publicly accessible — insecure design"),
    ("admin", "A01", "Administrative interface exposed — broken access control"),
    ("internal", "A01", "Internal API or system accessible externally — broken access control"),
    ("api", "A05", "API endpoint publicly enumerable — potential misconfiguration"),
    ("subdomain", "A05", "Broad subdomain exposure — attack surface misconfiguration"),
    ("technology", "A06", "Technology fingerprinting — potential vulnerable/outdated components"),
    ("wordpress", "A06", "WordPress installation detected — verify for outdated plugins/core"),
    ("drupal", "A06", "Drupal installation detected — verify for outdated modules"),
    ("shopify", "A04", "E-commerce platform detected — verify secure design of checkout flow"),
]


def map_finding_to_owasp(finding_text: str) -> dict[str, str]:
    """Return the best OWASP Top 10 category match for a finding string."""
    text_lower = finding_text.lower()
    for keyword, code, rationale in FINDING_OWASP_MAP:
        if keyword in text_lower:
            return {
                "code": code,
                "category": OWASP_CATEGORIES.get(code, code),
                "rationale": rationale,
            }
    # Default to Security Misconfiguration as the most common passive finding category
    return {
        "code": "A05",
        "category": OWASP_CATEGORIES["A05"],
        "rationale": "External exposure indicator consistent with security misconfiguration",
    }


# ---------------------------------------------------------------------------
# Attack Path Builder
# ---------------------------------------------------------------------------

ATTACK_PATHS: list[tuple[str, list[str]]] = [
    (
        "hsts",
        [
            "Missing HSTS Header",
            "HTTP Downgrade Attack Initiated",
            "Session Cookie Intercepted over HTTP",
            "Authenticated Session Hijacked",
            "Full Account Takeover — User Data Accessed",
        ],
    ),
    (
        "content-security-policy",
        [
            "Missing Content-Security-Policy",
            "Malicious Script Injected via XSS",
            "User Browser Executes Attacker Code",
            "Session Token / Credentials Exfiltrated",
            "Account Compromised — Data Breach Risk",
        ],
    ),
    (
        "x-frame-options",
        [
            "Missing X-Frame-Options",
            "Application Embedded in Attacker-Controlled iFrame",
            "Clickjacking UI Overlay Constructed",
            "User Performs Authenticated Action Unknowingly",
            "Funds Transfer / Data Modification Executed",
        ],
    ),
    (
        "ssl",
        [
            "Expired / Invalid TLS Certificate",
            "MITM Proxy Positioned Between Client and Server",
            "Encrypted Session Decrypted by Attacker",
            "Credentials and Session Tokens Captured",
            "Customer Account Credentials Harvested at Scale",
        ],
    ),
    (
        "port 3389",
        [
            "RDP Port 3389 Publicly Exposed",
            "Automated Credential Brute-Force Scan Hits Endpoint",
            "Valid Credential Pair Discovered",
            "Attacker Establishes Remote Desktop Session",
            "Lateral Movement / Ransomware Deployment",
        ],
    ),
    (
        "port 22",
        [
            "SSH Port 22 Publicly Exposed",
            "Passive Recon Identifies SSH Service Version",
            "Credential Stuffing / Key Brute-Force Attempted",
            "Shell Access Gained",
            "Data Exfiltration or Persistent Backdoor Installed",
        ],
    ),
    (
        "port 3306",
        [
            "MySQL Port 3306 Publicly Reachable",
            "Database Version Fingerprinted Passively",
            "Known CVE or Credential Attack Launched",
            "SQL Shell or Direct DB Access Obtained",
            "Full Customer Dataset Exfiltrated",
        ],
    ),
    (
        "redis",
        [
            "Redis Port 6379 Publicly Exposed (No Auth by Default)",
            "Attacker Connects Directly to Redis Instance",
            "Cache Data, Session Tokens Dumped",
            "Arbitrary Command Execution via CONFIG SET",
            "Host Server Compromised via Cron / SSH Key Injection",
        ],
    ),
    (
        "staging",
        [
            "Staging / Pre-Production Environment Exposed",
            "Weaker Auth Controls or Debug Features Active",
            "Attacker Extracts Internal API Structure / Test Credentials",
            "Test Credentials Reused on Production Systems",
            "Production Environment Compromised",
        ],
    ),
    (
        "admin",
        [
            "Administrative Interface Publicly Accessible",
            "Login Endpoint Exposed to Internet",
            "Credential Brute-Force / Phishing Attack Targeted",
            "Administrative Access Gained",
            "Full Application / Infrastructure Takeover",
        ],
    ),
    (
        "technology",
        [
            "Technology Stack Fingerprinted (Framework / Version Detected)",
            "Attacker Researches Known CVEs for Identified Version",
            "Exploit Code Sourced from Public Repositories",
            "Remote Code Execution Attempted",
            "Server Compromised — Arbitrary Command Execution",
        ],
    ),
    (
        "subdomain",
        [
            "High-Risk Subdomain Publicly Enumerable",
            "Internal API / Pre-Production System Identified",
            "Sensitive Configuration or Credentials Discovered",
            "Lateral Access to Production Adjacent Systems",
            "Data Exfiltration or Supply-Chain Attack Initiated",
        ],
    ),
]


def build_attack_path_for_finding(finding_text: str) -> list[str] | None:
    """Return an ordered attack chain list for the given finding text."""
    text_lower = finding_text.lower()
    for keyword, path in ATTACK_PATHS:
        if keyword.lower() in text_lower:
            return path
    # Generic fallback
    return [
        "External Exposure Signal Identified",
        "Passive Reconnaissance Incorporates Finding into Target Dossier",
        "Targeted Attack or Exploit Developed",
        "Vulnerability Leveraged for Initial Access",
        "Data Breach, Service Disruption, or Lateral Movement",
    ]


# ---------------------------------------------------------------------------
# Exposure Score Engine
# ---------------------------------------------------------------------------

EXPOSURE_SCORE_METHODOLOGY = {
    "description": (
        "The Exposure Score is a 1–10 composite metric representing the organisation's "
        "external attack surface as observed from a fully passive reconnaissance perspective. "
        "Higher scores indicate broader, more exploitable exposure."
    ),
    "scoring_factors": [
        {
            "factor": "Expired TLS Certificate",
            "points": "+2",
            "rationale": "An expired certificate disables transport security warnings and signals operational neglect.",
        },
        {
            "factor": "High-Risk Pattern Subdomains Detected",
            "points": "+2",
            "rationale": "Subdomains matching patterns such as 'dev', 'admin', 'staging' indicate pre-production or privileged surfaces.",
        },
        {
            "factor": "Sensitive Ports Publicly Reachable",
            "points": "+2",
            "rationale": "Ports such as 22 (SSH), 3306 (MySQL), 3389 (RDP) present direct attack vectors for credential attacks.",
        },
        {
            "factor": "Missing HSTS Header",
            "points": "+1",
            "rationale": "Absence of Strict-Transport-Security enables protocol downgrade and session interception.",
        },
        {
            "factor": "Missing Content-Security-Policy",
            "points": "+1",
            "rationale": "Absence of CSP leaves the application unprotected against cross-site scripting injection.",
        },
        {
            "factor": "Missing X-Frame-Options",
            "points": "+1",
            "rationale": "Without frame protection, authenticated interfaces are vulnerable to clickjacking.",
        },
        {
            "factor": "Large Subdomain Attack Surface (>5 hosts)",
            "points": "+1",
            "rationale": "A broad subdomain footprint increases enumeration potential and the probability of a misconfigured host.",
        },
    ],
    "thresholds": {
        "Low (1–3)": "Minimal observable exposure. Basic hygiene controls appear to be in place.",
        "Medium (4–7)": "Moderate exposure. Several risk indicators present; structured remediation recommended within 60 days.",
        "High (8–10)": "Significant external exposure. Immediate prioritised remediation required.",
    },
    "baseline": 1,
    "maximum": 10,
}


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
# Preliminary Risk Buckets with OWASP Mapping
# ---------------------------------------------------------------------------

def build_risk_preliminary(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Create contextual risk buckets enriched with business language and OWASP categories."""
    high: list[dict[str, str]] = []
    medium: list[dict[str, str]] = []
    low: list[dict[str, str]] = []

    ssl_summary = scan_data.get("ssl_summary", {})
    security_headers = scan_data.get("security_headers", {})
    subdomains = scan_data.get("subdomains", [])
    open_ports = scan_data.get("open_ports", [])
    tech_stack = scan_data.get("tech_stack", [])

    def _finding(text: str) -> dict[str, str]:
        owasp = map_finding_to_owasp(text)
        attack_path = build_attack_path_for_finding(text)
        return {
            "text": text,
            "owasp_code": owasp["code"],
            "owasp_category": owasp["category"],
            "owasp_rationale": owasp["rationale"],
            "attack_path": attack_path,
        }

    if ssl_summary.get("expired") is True:
        high.append(_finding(
            "Expired SSL/TLS certificate — HTTPS connections will display browser security warnings, "
            "eroding user trust and enabling potential interception."
        ))

    sensitive_open = [p for p in open_ports if p in SENSITIVE_PORTS]
    if sensitive_open:
        port_list = ", ".join(str(p) for p in sensitive_open)
        high.append(_finding(
            f"Sensitive service ports publicly reachable ({port_list}) — direct attack surface for "
            "credential brute-force, vulnerability exploitation, and lateral movement."
        ))

    missing: list[str] = security_headers.get("missing", [])
    missing_lower = [h.lower() for h in missing]

    if "strict-transport-security" in missing_lower:
        medium.append(_finding(
            "HSTS header absent — browsers may permit unencrypted HTTP connections, exposing "
            "session tokens to network-level interception."
        ))
    if "content-security-policy" in missing_lower:
        medium.append(_finding(
            "Content-Security-Policy header absent — application is unprotected against cross-site "
            "scripting (XSS) and content-injection attacks."
        ))
    if "x-frame-options" in missing_lower:
        medium.append(_finding(
            "X-Frame-Options header absent — application may be embeddable in third-party frames, "
            "enabling clickjacking attacks against authenticated users."
        ))

    pattern_hosts = _flag_pattern_subdomains(subdomains)
    if pattern_hosts:
        host_list = ", ".join(pattern_hosts[:5])
        ellipsis = f" (+{len(pattern_hosts) - 5} more)" if len(pattern_hosts) > 5 else ""
        medium.append(_finding(
            f"High-risk pattern subdomains publicly reachable: {host_list}{ellipsis} — these hosts "
            "commonly expose pre-production builds, administrative panels, or internal APIs "
            "with weaker security controls."
        ))

    uncommon = [p for p in open_ports if p not in COMMON_WEB_PORTS and p not in SENSITIVE_PORTS]
    if uncommon:
        port_list = ", ".join(str(p) for p in uncommon)
        medium.append(_finding(
            f"Non-standard ports publicly reachable ({port_list}) — service identification and "
            "version-probing by external parties is feasible via passive observation."
        ))

    if ssl_summary.get("reachable") is True and not ssl_summary.get("expired"):
        low.append(_finding("Valid TLS endpoint reachable. Certificate chain and expiry details collected."))
    if tech_stack:
        low.append(_finding(
            f"Technology stack fingerprinted ({len(tech_stack)} indicators). "
            "Public exposure of framework and version information may inform targeted research."
        ))
    if len(subdomains) > 5:
        low.append(_finding(
            f"{len(subdomains)} resolvable subdomains discovered. Broad subdomain exposure increases "
            "overall attack surface and enumeration potential."
        ))
    if not medium and not high:
        low.append(_finding(
            "No immediate high-confidence risk indicators identified from passive observation. "
            "Continued monitoring is recommended."
        ))

    return {"high": high, "medium": medium, "low": low}


# ---------------------------------------------------------------------------
# Assessment Metadata
# ---------------------------------------------------------------------------

def build_assessment_metadata(
    domain: str,
    timestamp: str,
    analyst_name: str,
    assessment_type: str,
    scanner_version: str,
) -> dict[str, str]:
    """Build the Assessment Metadata block for report header."""
    return {
        "assessment_type": assessment_type,
        "scope": f"External passive reconnaissance of {domain} and its publicly observable subdomain infrastructure",
        "timestamp": timestamp,
        "scanner_version": scanner_version,
        "analyst_name": analyst_name,
        "methodology": (
            "Passive external reconnaissance only. All data collected from publicly accessible sources "
            "including: HTTPS certificate inspection, HTTP response header analysis, DNS record enumeration, "
            "certificate transparency log queries (crt.sh), favicon hash fingerprinting, and TCP port probing "
            "of well-known service ports. No authentication, exploitation, or active intrusive testing "
            "was performed at any stage."
        ),
    }


# ---------------------------------------------------------------------------
# Main Output Builder
# ---------------------------------------------------------------------------

def build_structured_output(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Build the complete structured JSON payload with Exposure Score and all new metadata."""
    subdomains: list[str] = scan_data.get("subdomains", [])
    ssl_summary: dict[str, Any] = scan_data.get("ssl_summary", {})
    security_headers: dict[str, Any] = scan_data.get("security_headers", {})
    open_ports: list[int] = scan_data.get("open_ports", [])
    tech_stack: list[str] = scan_data.get("tech_stack", [])
    dns_records: dict[str, Any] = scan_data.get("dns_records", {})
    favicon_fp: dict[str, Any] = scan_data.get("favicon_fingerprint", {})
    analyst_name: str = scan_data.get("analyst_name", "SentinelX Automated Engine")
    assessment_type: str = scan_data.get("assessment_type", "External Passive Reconnaissance")
    scanner_version: str = scan_data.get("scanner_version", SCANNER_VERSION)
    timestamp: str = scan_data.get("timestamp", datetime.now(timezone.utc).isoformat())
    domain: str = scan_data.get("domain", "unknown")

    missing_headers: list[str] = security_headers.get("missing", [])
    attack_surface = build_attack_surface(
        subdomains, ssl_summary, security_headers, open_ports, tech_stack
    )
    exposure_score, exposure_level = compute_exposure_score(
        ssl_summary, subdomains, open_ports, missing_headers
    )
    risk_preliminary = build_risk_preliminary(scan_data)
    assessment_metadata = build_assessment_metadata(
        domain, timestamp, analyst_name, assessment_type, scanner_version
    )

    return {
        "domain": domain,
        "timestamp": timestamp,
        "assessment_metadata": assessment_metadata,
        "subdomains": subdomains,
        "ssl_summary": ssl_summary,
        "security_headers": security_headers,
        "tech_stack": tech_stack,
        "open_ports": open_ports,
        "dns_records": dns_records,
        "favicon_fingerprint": favicon_fp,
        "attack_surface": attack_surface,
        "exposure_score": exposure_score,
        "exposure_level": exposure_level,
        "exposure_score_methodology": EXPOSURE_SCORE_METHODOLOGY,
        "risk_preliminary": risk_preliminary,
    }


def save_json(data: dict[str, Any], path: str) -> None:
    """Write JSON to disk with stable formatting."""
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
    LOGGER.info("Saved JSON output to %s", path)
