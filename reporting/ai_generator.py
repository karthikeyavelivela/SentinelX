"""AI report generation from structured scanner output."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

LOGGER = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a professional cybersecurity analyst specializing in external SaaS exposure "
    "intelligence. Your job is to convert structured scan data into executive-ready security "
    "reports. Be concise, professional, and avoid fear-based language."
)

USER_PROMPT_TEMPLATE = """Provide:
- ExecutiveSummary (1 paragraph)
- Findings array with:
    Issue
    Category (High/Medium/Low)
    Description
    Remediation
- OverallRisk (High/Medium/Low)

Return STRICT JSON only.

Structured Scan Data:
{structured_json}
"""


def _extract_response_text(response: Any) -> str:
    """Extract text from OpenAI response object across SDK shapes."""
    if hasattr(response, "output_text") and response.output_text:
        return response.output_text
    if hasattr(response, "choices") and response.choices:
        return response.choices[0].message.content
    return str(response)


def _fallback_ai_report(structured_data: dict[str, Any], error_message: str) -> dict[str, Any]:
    """Generate deterministic fallback report when model call is unavailable."""
    risks = structured_data.get("risk_preliminary", {})
    findings: list[dict[str, str]] = []

    for category in ("high", "medium", "low"):
        for item in risks.get(category, []):
            findings.append(
                {
                    "Issue": item,
                    "Category": category.capitalize(),
                    "Description": item,
                    "Remediation": "Review finding and apply standard hardening controls.",
                }
            )

    overall = "High" if risks.get("high") else "Medium" if risks.get("medium") else "Low"
    return {
        "ExecutiveSummary": "Passive external exposure checks were completed successfully. "
        "This fallback report was generated because the AI service was unavailable.",
        "Findings": findings,
        "OverallRisk": overall,
        "GenerationNote": error_message,
    }


def generate_ai_report(
    structured_input_path: str = "structured_output.json",
    output_path: str = "ai_report.json",
) -> dict[str, Any]:
    """Generate AI-enriched JSON report using gpt-4o-mini."""
    with open(structured_input_path, "r", encoding="utf-8") as file:
        structured_data = json.load(file)

    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        report = _fallback_ai_report(structured_data, "OPENAI_API_KEY is not configured.")
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
        return report

    try:
        client = OpenAI(api_key=api_key)
        user_prompt = USER_PROMPT_TEMPLATE.format(
            structured_json=json.dumps(structured_data, indent=2)
        )
        response = client.responses.create(
            model="gpt-4o-mini",
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )

        raw_text = _extract_response_text(response).strip()
        ai_json = json.loads(raw_text)
    except Exception as exc:
        LOGGER.warning("OpenAI generation failed, using fallback summary: %s", exc)
        ai_json = _fallback_ai_report(structured_data, f"AI generation error: {exc}")

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(ai_json, file, indent=2)
    return ai_json

