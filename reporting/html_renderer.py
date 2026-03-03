"""HTML report renderer for executive-ready premium output."""

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
    """Render the premium HTML report using Jinja2 template."""
    LOGGER.info("Rendering HTML report to %s", output_path)
    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_name)

    # ------------------------------------------------------------------ #
    # Build Jinja2 context from structured and AI data
    # ------------------------------------------------------------------ #
    overall_risk = ai_data.get("OverallRisk", structured_data.get("exposure_level", "Low"))
    executive_summary = ai_data.get("ExecutiveSummary", "No summary available.")
    findings = ai_data.get("Findings", [])
    attack_surface = structured_data.get("attack_surface", {})
    exposure_score = structured_data.get("exposure_score", 1)
    exposure_level = structured_data.get("exposure_level", "Low")

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
    )

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(rendered)
    LOGGER.info("HTML report successfully written to %s", output_path)
    return output_path
