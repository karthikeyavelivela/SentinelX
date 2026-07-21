"""Structured output formatter for SentinelX reports."""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

SENSITIVE_PORTS: set[int] = {21, 22, 23, 25, 3306, 3389, 5432, 5900, 6379, 27017}
HIGH_RISK_PATTERNS: tuple[str, ...] = (
    "dev",
    "staging",
    "test",
    "beta",
    "admin",
    "api",
    "internal",
    "preprod",
    "uat",
    "mgmt",
    "management",
    "staff",
    "secret",
)

OWASP_MAP: dict[str, str] = {
    "tls": "A02:2021 - Cryptographic Failures",
    "header": "A05:2021 - Security Misconfiguration",
    "port": "A05:2021 - Security Misconfiguration",
    "subdomain": "A05:2021 - Security Misconfiguration",
    "email": "A05:2021 - Security Misconfiguration",
}

REMEDIATION_MAP: dict[str, str] = {
    "strict-transport-security": "Set HSTS with a long max-age and includeSubDomains once HTTPS is consistent.",
    "content-security-policy": "Set a restrictive Content-Security-Policy and remove weak directives.",
    "x-frame-options": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    "x-content-type-options": "Set X-Content-Type-Options to nosniff.",
    "referrer-policy": "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
    "permissions-policy": "Disable browser capabilities that the application does not require.",
    "cross-origin-opener-policy": "Set Cross-Origin-Opener-Policy to same-origin where compatible.",
    "cross-origin-resource-policy": "Set Cross-Origin-Resource-Policy to same-site or same-origin where compatible.",
    "x-dns-prefetch-control": "Set X-DNS-Prefetch-Control to off on sensitive applications.",
}

BUSINESS_IMPACT_MAP: dict[str, str] = {
    "headers": (
        "Raises the odds that a client-side attack against site visitors succeeds — "
        "clickjacking, MIME-sniffing abuse, or injected script running in a real user's browser."
    ),
    "ports": (
        "A reachable database or admin service is one weak credential or unpatched CVE away "
        "from full compromise of that system and anything it can reach."
    ),
    "subdomains": (
        "The hostname signals a lower-security environment (dev, staging, admin) that is "
        "statistically more likely to run outdated software or skip production hardening."
    ),
    "takeover": (
        "Whoever claims the dangling DNS record can serve arbitrary content, including a "
        "phishing page, under the organization's own trusted domain name."
    ),
    "dns": (
        "Weak sender validation lets outside parties send convincing spoofed email as the "
        "organization, landing phishing directly in employee or customer inboxes."
    ),
    "ssl": (
        "Certificate or transport weaknesses erode the encrypted-connection guarantee visitors "
        "rely on, and can trigger browser warnings that block access or damage trust outright."
    ),
    "general": "Expands the attack surface an outside party can use as a starting point.",
}

ATTACK_PATH_MAP: dict[str, list[str]] = {
    "headers": [
        "Visitor's browser loads the page without the missing protection",
        "Attacker delivers a crafted page, script, or frame to that visitor",
        "The missing header fails to block the technique",
        "The browser executes or renders the attacker's content",
        "Session hijack, credential theft, or defacement follows",
    ],
    "ports": [
        "External port scan finds the service reachable from the internet",
        "Attacker fingerprints the service and its version",
        "Default credentials, a known CVE, or brute force is attempted",
        "The service is compromised or its data is exfiltrated directly",
        "Lateral movement into connected internal systems follows",
    ],
    "subdomains": [
        "Passive enumeration surfaces the high-risk hostname",
        "Attacker treats it as a lower-priority, weaker-controlled target",
        "Directory brute force or default-credential attempts follow",
        "Any exposed panel or API on that host becomes an entry point",
        "The foothold expands toward the primary production environment",
    ],
    "takeover": [
        "The DNS record still points at a decommissioned third-party service",
        "Attacker registers the same name on that provider",
        "The subdomain now resolves attacker-controlled content under a trusted domain",
        "Content is used for phishing, credential harvesting, or malware hosting",
        "Brand trust and any cookies scoped to the parent domain are abused",
    ],
    "dns": [
        "Attacker crafts an email using the organization's domain as the sender",
        "The SPF/DMARC gap fails to flag or quarantine it",
        "The message lands in the inbox looking legitimate",
        "The recipient trusts the sender and acts on the message",
        "Credential theft, wire fraud, or malware delivery follows",
    ],
    "ssl": [
        "The certificate expires or a transport weakness is identified",
        "Browsers begin warning visitors or blocking the connection outright",
        "Traffic becomes more susceptible to interception on hostile networks",
        "Sensitive form data is exposed in transit",
        "Trust in the site and its data handling is damaged",
    ],
    "general": [
        "Exposure is observed in the external scan output",
        "Attacker prioritizes the issue for further probing",
        "The weak control is targeted directly",
        "Access or misuse becomes possible",
        "Business impact follows",
    ],
}


def _module_ok(data_quality: dict[str, Any], module_name: str) -> bool:
    entry = data_quality.get(module_name, {})
    return bool(entry.get("success"))


def _severity_to_cvss(severity: str) -> float:
    return {
        "Critical": 9.5,
        "High": 8.0,
        "Medium": 6.0,
        "Low": 3.0,
    }.get(severity, 5.0)


def _finding_module(title: str) -> str:
    lowered = title.lower()
    if "header" in lowered:
        return "headers"
    if "port" in lowered:
        return "ports"
    if "spf" in lowered or "dmarc" in lowered:
        return "dns"
    if "takeover" in lowered:
        return "takeover"
    if "tls" in lowered or "certificate" in lowered:
        return "ssl"
    if "subdomain" in lowered:
        return "subdomains"
    return "general"


def _make_finding(
    idx: int,
    *,
    title: str,
    severity: str,
    description: str,
    evidence: str,
    owasp_category: str,
    remediation: str,
    affected_asset: str,
) -> dict[str, Any]:
    module = _finding_module(title)
    finding = {
        "id": f"F-{idx:03d}",
        "title": title,
        "severity": severity,
        "cvss_score": _severity_to_cvss(severity),
        "description": description,
        "evidence": evidence,
        "owasp_category": owasp_category,
        "remediation": remediation,
        "affected_asset": affected_asset,
        "module": module,
        "business_impact": BUSINESS_IMPACT_MAP.get(module, BUSINESS_IMPACT_MAP["general"]),
        "attack_path": ATTACK_PATH_MAP.get(module, ATTACK_PATH_MAP["general"]),
    }
    return {
        "id": str(finding.get("id", f"F-{idx:03d}")),
        "title": str(finding.get("title", "Untitled finding")),
        "severity": str(finding.get("severity", "Low")),
        "cvss_score": float(finding.get("cvss_score", 3.0)),
        "description": str(finding.get("description", "No description provided.")),
        "evidence": str(finding.get("evidence", "No evidence captured.")),
        "owasp_category": str(finding.get("owasp_category", "A05:2021 - Security Misconfiguration")),
        "remediation": str(finding.get("remediation", "Review and harden this exposure.")),
        "affected_asset": str(finding.get("affected_asset", "Unknown")),
        "module": str(finding.get("module", "general")),
        "business_impact": str(finding.get("business_impact", BUSINESS_IMPACT_MAP["general"])),
        "attack_path": list(finding.get("attack_path", ATTACK_PATH_MAP["general"])),
    }


def _build_findings(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    data_quality = scan_data.get("data_quality", {})
    domain = scan_data.get("domain", "unknown")

    ssl_data = scan_data.get("ssl", {})
    if _module_ok(data_quality, "ssl") and ssl_data.get("reachable") and ssl_data.get("expired"):
        findings.append(
            _make_finding(
                len(findings) + 1,
                title="TLS Certificate Expired",
                severity="High",
                description="The TLS certificate is expired and browsers may block or distrust the site.",
                evidence=f"valid_to={ssl_data.get('valid_to')}",
                owasp_category=OWASP_MAP["tls"],
                remediation="Renew the certificate and enable automated renewal before it expires again.",
                affected_asset=domain,
            )
        )

    if _module_ok(data_quality, "headers"):
        for row in scan_data.get("headers", {}).get("headers", []):
            if not isinstance(row, dict):
                continue
            status = str(row.get("status", "UNKNOWN")).upper()
            if status not in {"FAIL", "WARN"}:
                continue
            findings.append(
                _make_finding(
                    len(findings) + 1,
                    title=f"{'Missing' if status == 'FAIL' else 'Weak'} Security Header: {row.get('name')}",
                    severity="Medium" if status == "FAIL" else "Low",
                    description=str(row.get("note", "Security header weakness detected.")),
                    evidence=f"target_url={scan_data.get('headers', {}).get('target_url', f'https://{domain}')}",
                    owasp_category=OWASP_MAP["header"],
                    remediation=REMEDIATION_MAP.get(
                        str(row.get("name", "")).lower(),
                        str(row.get("recommendation", "Add this header in web server or gateway configuration.")),
                    ),
                    affected_asset=domain,
                )
            )

    ports = scan_data.get("ports", [])
    if _module_ok(data_quality, "ports"):
        for port in sorted(item for item in ports if item in SENSITIVE_PORTS):
            findings.append(
                _make_finding(
                    len(findings) + 1,
                    title=f"Sensitive Port Exposed: {port}",
                    severity="High",
                    description=f"Service on TCP {port} is reachable from the public internet.",
                    evidence=f"open_port={port}",
                    owasp_category=OWASP_MAP["port"],
                    remediation="Restrict this port at firewall or security-group level to trusted source ranges only.",
                    affected_asset=domain,
                )
            )

    if _module_ok(data_quality, "subdomains"):
        for host in scan_data.get("subdomains", []):
            labels = str(host).lower().split(".")
            if any(label in HIGH_RISK_PATTERNS for label in labels):
                findings.append(
                    _make_finding(
                        len(findings) + 1,
                        title="High-Risk Subdomain Naming Pattern",
                        severity="Medium",
                        description="The hostname suggests admin, staging, development, or internal functionality.",
                        evidence=f"subdomain={host}",
                        owasp_category=OWASP_MAP["subdomain"],
                        remediation="Review whether this subdomain should be public. Restrict or remove it if not needed.",
                        affected_asset=host,
                    )
                )

    if _module_ok(data_quality, "takeover"):
        for item in scan_data.get("takeover_findings", []):
            subdomain = str(item.get("subdomain", "unknown"))
            confidence = str(item.get("confidence", "medium")).lower()
            severity = "High" if confidence == "high" else "Medium"
            fingerprint = item.get("fingerprint_matched") or "Known vulnerable service CNAME pattern"
            findings.append(
                _make_finding(
                    len(findings) + 1,
                    title=f"Potential Subdomain Takeover: {subdomain}",
                    severity=severity,
                    description="The subdomain points to a third-party service pattern associated with dangling DNS risk.",
                    evidence=f"service={item.get('service')} fingerprint={fingerprint}",
                    owasp_category=OWASP_MAP["subdomain"],
                    remediation="Confirm ownership at the provider or remove the stale DNS record.",
                    affected_asset=subdomain,
                )
            )

    if _module_ok(data_quality, "dns"):
        dns_data = scan_data.get("dns", {})
        spf_analysis = dns_data.get("spf_analysis", {})
        dmarc_analysis = dns_data.get("dmarc_analysis", {})

        if spf_analysis.get("severity") in {"High", "Medium"}:
            findings.append(
                _make_finding(
                    len(findings) + 1,
                    title=f"SPF Posture: {spf_analysis.get('status', 'unknown')}",
                    severity=str(spf_analysis.get("severity", "Medium")),
                    description=str(spf_analysis.get("summary", "SPF review recommended.")),
                    evidence=f"spf_record={dns_data.get('spf_record') or 'not_found'}",
                    owasp_category=OWASP_MAP["email"],
                    remediation=str(spf_analysis.get("recommendation", "Review and harden SPF.")),
                    affected_asset=domain,
                )
            )

        if dmarc_analysis.get("severity") in {"High", "Medium"}:
            findings.append(
                _make_finding(
                    len(findings) + 1,
                    title=f"DMARC Posture: {dmarc_analysis.get('status', 'unknown')}",
                    severity=str(dmarc_analysis.get("severity", "Medium")),
                    description=str(dmarc_analysis.get("summary", "DMARC review recommended.")),
                    evidence=f"dmarc_record={dns_data.get('dmarc_record') or 'not_found'}",
                    owasp_category=OWASP_MAP["email"],
                    remediation=str(dmarc_analysis.get("recommendation", "Review and harden DMARC.")),
                    affected_asset=domain,
                )
            )

    return findings


def _risk_buckets(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = {"critical": [], "high": [], "medium": [], "low": []}
    for finding in findings:
        severity = finding["severity"].lower()
        key = severity if severity in buckets else "low"
        buckets[key].append(
            {
                "text": finding["title"],
                "business_impact": finding.get("business_impact", BUSINESS_IMPACT_MAP["general"]),
                "attack_path": finding.get("attack_path", ATTACK_PATH_MAP["general"]),
            }
        )
    return buckets


def _compute_exposure_score(
    scan_data: dict[str, Any],
    severity_counts: dict[str, int],
) -> tuple[int, str]:
    """Score exposure from severity mix, with diminishing returns per tier.

    A straight linear sum lets a pile of low-severity findings (e.g. nine
    missing headers, all Medium) out-rank the presence of a single real
    Critical, and can blow past 100 on volume alone. Square-root dampening
    per tier means the 4th Medium finding adds much less than the 1st, so
    volume can't manufacture a false Critical. The severity *label* is then
    floored by the worst confirmed finding, not by the numeric score, so the
    two never contradict each other in the report.
    """
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)
    low = severity_counts.get("Low", 0)

    base = 26 * math.sqrt(critical) + 16 * math.sqrt(high) + 7 * math.sqrt(medium) + 2.5 * math.sqrt(low)

    context_bonus = 0.0
    if len(scan_data.get("subdomains", [])) >= 15:
        context_bonus += 3
    if len(scan_data.get("ports", [])) >= 3:
        context_bonus += 5
    if scan_data.get("dns", {}).get("dmarc_analysis", {}).get("status") == "missing":
        context_bonus += 5
    if scan_data.get("dns", {}).get("spf_analysis", {}).get("status") in {"missing", "neutral"}:
        context_bonus += 5

    score = min(round(base + context_bonus), 100)

    if critical >= 1:
        level = "Critical"
    elif high >= 2 or (high >= 1 and score >= 45):
        level = "High"
    elif high >= 1 or medium >= 1 or score >= 20:
        level = "Medium"
    else:
        level = "Low"
    return score, level


def _build_completeness_note(data_quality: dict[str, Any]) -> str:
    total = len(data_quality)
    failed = sum(1 for _, item in data_quality.items() if item.get("status") == "failed")
    skipped = sum(1 for _, item in data_quality.items() if item.get("status") == "skipped")
    if failed == 0 and skipped == 0:
        return "All collection modules completed successfully."
    notes: list[str] = []
    if failed:
        notes.append(f"{failed} module(s) returned partial data")
    if skipped:
        notes.append(f"{skipped} module(s) were skipped by scope")
    return ", ".join(notes) + ". Exposure scoring may understate risk."


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in findings:
        severity = str(item.get("severity", "Low"))
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _build_module_sections(scan_data: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped_findings: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        grouped_findings.setdefault(str(finding.get("module", "general")), []).append(finding)

    headers_rows = scan_data.get("headers", {}).get("headers", [])
    dns_data = scan_data.get("dns", {})
    sections = [
        {
            "module": "dns",
            "title": "DNS and Email Authentication",
            "summary": "Mail safety controls, DNS records, and spoofing posture.",
            "findings": grouped_findings.get("dns", []),
            "details": {
                "a_records": dns_data.get("a_records", []),
                "mx_records": dns_data.get("mx_records", []),
                "spf_record": dns_data.get("spf_record"),
                "dmarc_record": dns_data.get("dmarc_record"),
            },
        },
        {
            "module": "headers",
            "title": "Security Headers",
            "summary": "Browser-side protections visible on the public web response.",
            "findings": grouped_findings.get("headers", []),
            "details": {"headers": headers_rows},
        },
        {
            "module": "ssl",
            "title": "TLS and Certificate",
            "summary": "External encryption posture for the main site.",
            "findings": grouped_findings.get("ssl", []),
            "details": scan_data.get("ssl", {}),
        },
        {
            "module": "subdomains",
            "title": "Subdomains",
            "summary": "Publicly discoverable hostnames and naming risk.",
            "findings": grouped_findings.get("subdomains", []),
            "details": {"subdomains": scan_data.get("subdomains", [])},
        },
        {
            "module": "ports",
            "title": "Open Ports",
            "summary": "Network services reachable from the internet.",
            "findings": grouped_findings.get("ports", []),
            "details": {"ports": scan_data.get("ports", [])},
        },
        {
            "module": "takeover",
            "title": "Subdomain Takeover Signals",
            "summary": "Third-party hostname mappings that may be reclaimable.",
            "findings": grouped_findings.get("takeover", []),
            "details": {"takeover_findings": scan_data.get("takeover_findings", [])},
        },
    ]

    for module in sections:
        module_key = str(module["module"])
        module["business_impact"] = BUSINESS_IMPACT_MAP.get(module_key, BUSINESS_IMPACT_MAP["general"])
        module["attack_path"] = ATTACK_PATH_MAP.get(module_key, ATTACK_PATH_MAP["general"])
        # Findings already carry per-finding business_impact/attack_path for JSON/API
        # consumers, but within one module section they're identical for every row —
        # repeating that paragraph N times reads like a stuck tape. Show it once via
        # the module-level fields above instead.
        module["has_detail"] = bool(module["findings"]) or any(module["details"].values())

    # DNS/SSL/Subdomains/Ports sections with zero findings and zero raw detail are
    # pure "nothing to see here" filler — drop them instead of padding the report.
    return [module for module in sections if module["has_detail"]]


def _plain_english_summary(
    domain: str,
    severity_counts: dict[str, int],
    total_findings: int,
    subdomain_count: int,
) -> str:
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)

    if total_findings == 0:
        return (
            f"This scan of {domain} did not surface any exposure worth flagging from the outside. "
            f"That covers {subdomain_count} discovered subdomain(s) — keep an eye on it with periodic re-scans."
        )

    if critical or high:
        urgent = critical + high
        return (
            f"This scan of {domain} found {urgent} issue(s) rated high or critical, out of "
            f"{total_findings} total, across {subdomain_count} discovered subdomain(s). "
            "These are the exposures a real attacker would try first — fix those before anything else on this list."
        )

    if medium:
        return (
            f"This scan of {domain} found {total_findings} issue(s), the most severe rated medium, "
            f"across {subdomain_count} discovered subdomain(s). Nothing here is an immediate emergency, "
            "but each item narrows the gap an attacker needs."
        )

    return (
        f"This scan of {domain} found {total_findings} low-severity issue(s) across {subdomain_count} "
        "discovered subdomain(s) — minor hardening gaps rather than active exposure."
    )


def _closing_line(analyst_email: str | None) -> str:
    if analyst_email:
        return f"Questions or remediation support: {analyst_email}"
    return "Contact the assessing analyst for remediation support and a follow-up re-scan."


def _build_executive_summary(
    scan_data: dict[str, Any],
    findings: list[dict[str, Any]],
    exposure_score: int,
    exposure_level: str,
) -> dict[str, Any]:
    severity_counts = _severity_counts(findings)
    urgent = sorted(
        findings,
        key=lambda item: (
            {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(str(item.get("severity")), 4),
            str(item.get("title", "")),
        ),
    )[:3]
    top_fixes = [
        {
            "finding": item["title"],
            "fix": item["remediation"],
            "severity": item["severity"],
            "business_impact": item["business_impact"],
        }
        for item in urgent
    ]
    domain = scan_data.get("domain", "unknown")
    return {
        "title": "EXECUTIVE SUMMARY",
        "domain": domain,
        "scan_date": str(scan_data.get("scan_start_time", scan_data.get("scan_timestamp", "")))[:10],
        "overall_risk_score": exposure_score,
        "overall_risk_level": exposure_level.upper(),
        "critical_findings": severity_counts.get("Critical", 0),
        "high_findings": severity_counts.get("High", 0),
        "subdomains_discovered": len(scan_data.get("subdomains", [])),
        "open_ports": len(scan_data.get("ports", [])),
        "plain_english_summary": _plain_english_summary(domain, severity_counts, len(findings), len(scan_data.get("subdomains", []))),
        "top_urgent_findings": top_fixes,
        "top_business_impact": (
            top_fixes[0]["business_impact"]
            if top_fixes
            else "No significant business impact identified from this scan."
        ),
        "closing_line": _closing_line(scan_data.get("analyst_email")),
    }


def build_structured_output(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Build normalized structured output for downstream reporting."""
    findings = _build_findings(scan_data)
    data_quality = scan_data.get("data_quality", {})
    severity_counts = _severity_counts(findings)
    exposure_score, exposure_level = _compute_exposure_score(scan_data, severity_counts)
    risk_preliminary = _risk_buckets(findings)

    return {
        "domain": scan_data.get("domain", "unknown"),
        "scan_timestamp": scan_data.get("scan_timestamp"),
        "scan_start_time": scan_data.get("scan_start_time"),
        "assessment_metadata": {
            "assessment_type": scan_data.get("assessment_type", "External Passive Reconnaissance"),
            "timestamp": scan_data.get("scan_timestamp"),
            "scan_start_time": scan_data.get("scan_start_time"),
            "analyst_name": scan_data.get("analyst_name", "SentinelX Automated Engine"),
            "analyst_email": scan_data.get("analyst_email"),
            "scanner_version": scan_data.get("scanner_version", "2.1.0"),
            "scope": str(scan_data.get("scope", "standard")),
            "methodology": (
                "DNS, TLS metadata, certificate transparency, passive email control review, "
                "HTTP response header checks, lightweight TCP port probing, and subdomain takeover heuristics."
            ),
            "pdf_status": "pending",
            "pdf_engine": "pending",
        },
        "subdomains": scan_data.get("subdomains", []),
        "ssl": scan_data.get("ssl", {}),
        "headers": scan_data.get("headers", {}),
        "ports": scan_data.get("ports", []),
        "favicon": scan_data.get("favicon", {}),
        "techstack": scan_data.get("techstack", []),
        "dns": scan_data.get("dns", {}),
        "takeover_findings": scan_data.get("takeover_findings", []),
        "phase_timings": scan_data.get("phase_timings", {}),
        "scan_duration_seconds": scan_data.get("scan_duration_seconds", 0.0),
        "data_quality": data_quality,
        "completeness_note": _build_completeness_note(data_quality),
        "findings": findings,
        "findings_table": [
            {
                "severity": item["severity"],
                "finding": item["title"],
                "module": item["module"],
                "recommendation": item["remediation"],
            }
            for item in findings
        ],
        "severity_counts": severity_counts,
        "risk_preliminary": risk_preliminary,
        "exposure_score": exposure_score,
        "exposure_level": exposure_level,
        "executive_summary": _build_executive_summary(scan_data, findings, exposure_score, exposure_level),
        "attack_surface": {
            "total_subdomains": len(scan_data.get("subdomains", [])),
            "high_risk_subdomains": [
                host
                for host in scan_data.get("subdomains", [])
                if any(label in HIGH_RISK_PATTERNS for label in str(host).lower().split("."))
            ],
            "tls_status": (
                "Unreachable"
                if not scan_data.get("ssl", {}).get("reachable")
                else "Expired"
                if scan_data.get("ssl", {}).get("expired")
                else "Valid"
            ),
            "sensitive_open_ports": [port for port in scan_data.get("ports", []) if port in SENSITIVE_PORTS],
            "tech_stack_summary": [
                f"{item.get('name')} ({item.get('confidence')})"
                if isinstance(item, dict)
                else str(item)
                for item in scan_data.get("techstack", [])
            ],
            "takeover_candidates": scan_data.get("takeover_findings", []),
        },
        "module_sections": _build_module_sections(scan_data, findings),
        "exposure_score_methodology": {
            "description": "Exposure score is based on confirmed findings, exposed services, and email control weaknesses.",
            "minimum": 0,
            "maximum": 100,
        },
    }


def save_json(data: dict[str, Any], path: str) -> None:
    """Write JSON to disk with stable formatting."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
    LOGGER.info("Saved JSON output to %s", output_path)
