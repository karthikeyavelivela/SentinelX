"""HTML report renderer for executive-ready output."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

LOGGER = logging.getLogger(__name__)


def render_html_report(
    structured_data: dict[str, Any],
    ai_data: dict[str, Any],
    output_path: str = "final_report.html",
    template_name: str = "report_template.html",
) -> str:
    """Render final HTML report using Jinja2 template."""
    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_name)

    overall_risk = ai_data.get("OverallRisk", "Low")
    rendered = template.render(
        domain=structured_data.get("domain", "unknown"),
        report_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        executive_summary=ai_data.get("ExecutiveSummary", "No summary generated."),
        overall_risk=overall_risk,
        findings=ai_data.get("Findings", []),
        recommendations=[f.get("Remediation", "") for f in ai_data.get("Findings", []) if f.get("Remediation")],
        structured=structured_data,
    )

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(rendered)
    LOGGER.info("HTML report generated at %s", output_path)
    return output_path

