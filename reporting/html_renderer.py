"""HTML report renderer for executive-ready premium output — consulting-grade edition."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

LOGGER = logging.getLogger(__name__)

# Well-known port → service-name mapping (passive reference only)
PORT_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP/TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2222: "SSH (alt)",
    2375: "Docker (unencrypted)",
    2376: "Docker TLS",
    3000: "Dev Server",
    3306: "MySQL",
    3389: "RDP",
    4443: "HTTPS (alt)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP (alt)",
    8443: "HTTPS (alt)",
    8888: "Jupyter / Dev",
    9000: "PHP-FPM / Dev",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

SENSITIVE_PORTS: set[int] = {21, 22, 23, 25, 3306, 3389, 5432, 5900, 6379, 27017}
COMMON_WEB_PORTS: set[int] = {80, 443, 8080, 8443}

CRITICAL_HEADERS: list[tuple[str, str]] = [
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
]

HIGH_RISK_PATTERNS = {
    "dev", "staging", "test", "beta", "admin", "api", "internal",
    "preprod", "uat", "mgmt", "management", "staff", "secret",
}


def _build_port_appendix(open_ports: list[int]) -> list[dict[str, str]]:
    rows = []
    for port in sorted(open_ports):
        service = PORT_SERVICES.get(port, "Unknown")
        if port in SENSITIVE_PORTS:
            classification = "High Exposure"
        elif port in COMMON_WEB_PORTS:
            classification = "Standard Web"
        else:
            classification = "Non-Standard"
        rows.append({"port": port, "service": service, "classification": classification})
    return rows


def _build_headers_appendix(security_headers: dict[str, Any]) -> list[dict[str, str]]:
    present: dict[str, str] = {
        k.lower(): v for k, v in security_headers.get("present", {}).items()
    }
    rows = []
    seen: set[str] = set()
    for key, display in CRITICAL_HEADERS:
        seen.add(key)
        if key in present:
            rows.append({"name": display, "present": "Yes", "value": present[key][:120]})
        else:
            rows.append({"name": display, "present": "No", "value": "—"})
    for key, value in present.items():
        if key not in seen:
            rows.append({"name": key, "present": "Yes", "value": str(value)[:120]})
    return rows


def _build_ssl_appendix(ssl_summary: dict[str, Any]) -> dict[str, str]:
    def extract_cn(field: Any) -> str:
        if not field:
            return "—"
        try:
            for group in field:
                for pair in group:
                    if pair[0] in ("commonName", "CN"):
                        return pair[1]
        except Exception:
            pass
        return str(field)

    expiry = ssl_summary.get("valid_to") or "—"
    days = ssl_summary.get("days_remaining")
    return {
        "reachable": "Yes" if ssl_summary.get("reachable") else "No",
        "issuer": extract_cn(ssl_summary.get("issuer")),
        "subject": extract_cn(ssl_summary.get("subject")),
        "valid_from": ssl_summary.get("valid_from") or "—",
        "valid_to": expiry,
        "days_remaining": str(days) if days is not None else "—",
        "tls_version": ssl_summary.get("tls_version") or "—",
        "cipher": ssl_summary.get("cipher") or "—",
        "expired": "Yes" if ssl_summary.get("expired") else "No",
        "error": ssl_summary.get("error") or "",
    }


def _build_dns_appendix(dns_records: dict[str, Any]) -> dict[str, Any]:
    """Build a display-ready DNS records block."""
    return {
        "a_records": dns_records.get("a_records", []),
        "mx_records": dns_records.get("mx_records", []),
        "txt_records": dns_records.get("txt_records", []),
        "cname_records": dns_records.get("cname_records", []),
        "spf_record": dns_records.get("spf_record"),
        "dmarc_record": dns_records.get("dmarc_record"),
        "error": dns_records.get("error"),
    }


def _collect_attack_paths(findings: list[dict[str, Any]], risk_preliminary: dict) -> list[dict]:
    """Gather unique attack paths from findings for the dedicated Attack Path section."""
    paths = []
    seen_paths: set[str] = set()

    # From AI findings
    for finding in findings:
        attack_path = finding.get("AttackPath")
        risk_cat = finding.get("RiskCategory", "Low").lower()
        if attack_path and isinstance(attack_path, list) and risk_cat in ("high", "medium"):
            key = finding.get("Issue", "")
            if key not in seen_paths:
                seen_paths.add(key)
                paths.append({
                    "issue": finding.get("Issue", "Finding"),
                    "risk": risk_cat,
                    "steps": attack_path,
                })

    # Fall back to risk_preliminary attack paths if no AI findings
    if not paths:
        for level in ("high", "medium"):
            for item in risk_preliminary.get(level, []):
                if isinstance(item, dict):
                    ap = item.get("attack_path")
                    if ap:
                        key = item.get("text", "")[:60]
                        if key not in seen_paths:
                            seen_paths.add(key)
                            paths.append({
                                "issue": item.get("text", "Finding")[:80],
                                "risk": level,
                                "steps": ap,
                            })
    return paths


def render_html_report(
    structured_data: dict[str, Any],
    ai_data: dict[str, Any],
    output_path: str = "final_report.html",
    template_name: str = "report_template.html",
) -> str:
    """Render the premium HTML report using Jinja2 template."""
    LOGGER.info("Rendering HTML report to %s", output_path)
    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_name)

    overall_risk = ai_data.get("OverallRisk", structured_data.get("exposure_level", "Low"))
    executive_summary = ai_data.get("ExecutiveSummary", "No summary available.")
    findings = ai_data.get("Findings", [])
    attack_surface = structured_data.get("attack_surface", {})
    exposure_score = structured_data.get("exposure_score", 1)
    exposure_level = structured_data.get("exposure_level", "Low")
    assessment_metadata = structured_data.get("assessment_metadata", {})
    exposure_score_methodology = structured_data.get("exposure_score_methodology", {})
    dns_records = structured_data.get("dns_records", {})
    risk_preliminary = structured_data.get("risk_preliminary", {})

    open_ports: list[int] = structured_data.get("open_ports", [])
    security_headers: dict[str, Any] = structured_data.get("security_headers", {})
    ssl_summary: dict[str, Any] = structured_data.get("ssl_summary", {})
    subdomains: list[str] = structured_data.get("subdomains", [])

    def is_high_risk(host: str) -> bool:
        return any(label in HIGH_RISK_PATTERNS for label in host.lower().split("."))

    appendix_ports = _build_port_appendix(open_ports)
    appendix_headers = _build_headers_appendix(security_headers)
    appendix_ssl = _build_ssl_appendix(ssl_summary)
    appendix_dns = _build_dns_appendix(dns_records)
    attack_paths = _collect_attack_paths(findings, risk_preliminary)

    # Cert transparency subdomains (all discovered, not just resolved)
    all_ct_subdomains = sorted(subdomains)

    rendered = template.render(
        domain=structured_data.get("domain", "unknown"),
        report_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        executive_summary=executive_summary,
        overall_risk=overall_risk,
        findings=findings,
        attack_surface=attack_surface,
        exposure_score=exposure_score,
        exposure_level=exposure_level,
        structured=structured_data,
        assessment_metadata=assessment_metadata,
        exposure_score_methodology=exposure_score_methodology,
        # Appendix context
        appendix_subdomains=subdomains,
        appendix_ports=appendix_ports,
        appendix_headers=appendix_headers,
        appendix_ssl=appendix_ssl,
        appendix_dns=appendix_dns,
        all_ct_subdomains=all_ct_subdomains,
        attack_paths=attack_paths,
        is_high_risk=is_high_risk,
    )

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(rendered)
    LOGGER.info("HTML report successfully written to %s", output_path)
    return output_path
