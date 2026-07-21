"""HTML report renderer for executive-ready premium output."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

LOGGER = logging.getLogger(__name__)

PORT_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP (alt)",
    8443: "HTTPS (alt)",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _build_port_appendix(open_ports: list[int]) -> list[dict[str, str]]:
    rows = []
    for port in sorted(open_ports):
        rows.append({"port": str(port), "service": PORT_SERVICES.get(port, "Unknown")})
    return rows


def _build_ssl_appendix(ssl_summary: dict[str, Any]) -> dict[str, str]:
    def extract_cn(field: Any) -> str:
        if not field:
            return "-"
        try:
            for group in field:
                for pair in group:
                    if pair[0] in ("commonName", "CN"):
                        return pair[1]
        except Exception:
            pass
        return str(field)

    return {
        "reachable": "Yes" if ssl_summary.get("reachable") else "No",
        "issuer": extract_cn(ssl_summary.get("issuer")),
        "subject": extract_cn(ssl_summary.get("subject")),
        "valid_from": ssl_summary.get("valid_from") or "-",
        "valid_to": ssl_summary.get("valid_to") or "-",
        "days_remaining": str(ssl_summary.get("days_remaining")) if ssl_summary.get("days_remaining") is not None else "-",
        "tls_version": ssl_summary.get("tls_version") or "-",
        "cipher": ssl_summary.get("cipher") or "-",
        "expired": "Yes" if ssl_summary.get("expired") else "No",
        "error": ssl_summary.get("error") or "",
    }


def render_html_report(
    structured_data: dict[str, Any],
    ai_data: dict[str, Any] | None,
    output_path: str = "final_report.html",
    template_name: str = "report_template.html",
) -> str:
    """Render the HTML report using the Jinja2 template."""
    LOGGER.info("Rendering HTML report to %s", output_path)
    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_name)

    executive_summary = structured_data.get("executive_summary", {})
    if ai_data and isinstance(ai_data.get("ExecutiveSummary"), dict):
        ai_summary = ai_data["ExecutiveSummary"]
        if ai_summary.get("OverallPosture"):
            executive_summary["plain_english_summary"] = ai_summary["OverallPosture"]

    rendered = template.render(
        domain=structured_data.get("domain", "unknown"),
        report_date=structured_data.get("scan_start_time", structured_data.get("scan_timestamp", "Unknown")),
        executive_summary=executive_summary,
        structured=structured_data,
        findings=structured_data.get("findings", []),
        findings_table=structured_data.get("findings_table", []),
        severity_counts=structured_data.get("severity_counts", {}),
        module_sections=structured_data.get("module_sections", []),
        comparison_report=structured_data.get("comparison_report", {}),
        ports_appendix=_build_port_appendix(structured_data.get("ports", [])),
        ssl_appendix=_build_ssl_appendix(structured_data.get("ssl", {})),
        ai_data=ai_data or {},
    )

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(rendered)
    LOGGER.info("HTML report successfully written to %s", output_path)
    return output_path
