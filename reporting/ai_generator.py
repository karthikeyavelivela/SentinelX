"""Optional AI report generation with deterministic fallback."""

from __future__ import annotations

import copy
import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

SYSTEM_PROMPT = "You are a principal security consultant. Produce concise, factual JSON only."

USER_PROMPT_TEMPLATE = """Return strict JSON:
{
  "ExecutiveSummary": {
    "OverallPosture": "...",
    "TopRiskOne": "...",
    "TopRiskTwo": "...",
    "RecommendedNextStep": "...",
    "PassiveAssessmentStatement": "..."
  },
  "OverallRisk": "Critical|High|Medium|Low"
}

Input scan JSON:
{structured_json}
"""


def _fallback_ai_report(structured_data: dict[str, Any]) -> dict[str, Any]:
    summary = structured_data.get("executive_summary", {})
    top_fixes = summary.get("top_urgent_findings", [])
    return {
        "ExecutiveSummary": {
            "OverallPosture": summary.get("plain_english_summary", "No summary available."),
            "TopRiskOne": top_fixes[0]["finding"] if len(top_fixes) > 0 else "No urgent findings recorded.",
            "TopRiskTwo": top_fixes[1]["finding"] if len(top_fixes) > 1 else "No second urgent finding recorded.",
            "RecommendedNextStep": "Fix the top issues first, then rerun the scan to confirm the public exposure is reduced.",
            "PassiveAssessmentStatement": "This assessment combines passive intelligence with lightweight live checks.",
        },
        "OverallRisk": structured_data.get("exposure_level", "Low"),
        "report_source": "deterministic_fallback",
    }


def _extract_response_text(response: Any) -> str:
    if hasattr(response, "output_text") and response.output_text:
        return response.output_text
    if hasattr(response, "choices") and response.choices:
        return response.choices[0].message.content
    return str(response)


def _is_internal_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved


def _redact_value(value: Any, *, subdomains: set[str]) -> Any:
    if isinstance(value, dict):
        return {key: _redact_value(item, subdomains=subdomains) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, subdomains=subdomains) for item in value]
    if isinstance(value, str):
        if _is_internal_ip(value):
            return "[redacted-internal-ip]"
        redacted = value
        for host in sorted(subdomains, key=len, reverse=True):
            redacted = redacted.replace(host, "[redacted-subdomain]")
        return redacted
    return value


def _redact_structured_payload(structured_data: dict[str, Any]) -> dict[str, Any]:
    redacted = copy.deepcopy(structured_data)
    domain = str(redacted.get("domain", ""))
    subdomains = {
        host
        for host in redacted.get("subdomains", [])
        if isinstance(host, str) and host and host != domain
    }
    redacted["subdomain_count"] = len(redacted.get("subdomains", []))
    redacted["subdomains"] = []

    dns_block = redacted.get("dns", {})
    if isinstance(dns_block, dict):
        dns_block["a_records"] = [
            ip for ip in dns_block.get("a_records", []) if not (isinstance(ip, str) and _is_internal_ip(ip))
        ]

    return _redact_value(redacted, subdomains=subdomains)


def generate_ai_report(
    *,
    structured_data: dict[str, Any] | None = None,
    structured_input_path: str = "structured_output.json",
    output_path: str = "ai_report.json",
    ai_mode: str = "openai",
) -> dict[str, Any]:
    """Generate an optional OpenAI-assisted summary, with deterministic fallback on failure."""
    if structured_data is None:
        with open(structured_input_path, "r", encoding="utf-8") as file:
            structured_data = json.load(file)

    api_key = os.getenv("OPENAI_API_KEY")
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if ai_mode != "openai" or not api_key:
        report = _fallback_ai_report(structured_data)
        report["report_source_reason"] = "missing_openai_api_key" if not api_key else "external_ai_disabled"
        with output.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
        return report

    try:
        sanitized = _redact_structured_payload(structured_data)
        from openai import OpenAI  # noqa: PLC0415

        client = OpenAI(api_key=api_key, timeout=30)
        response = client.responses.create(
            model="gpt-4o-mini",
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": USER_PROMPT_TEMPLATE.format(structured_json=json.dumps(sanitized, indent=2)),
                },
            ],
            temperature=0.2,
        )
        raw_text = _extract_response_text(response).strip()
        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        ai_json = json.loads(raw_text)
        ai_json["report_source"] = "openai_gpt4o_mini"
        ai_json["report_source_reason"] = "explicit_opt_in"
    except Exception as exc:
        LOGGER.warning("AI generation failed or timed out; using fallback: %s", exc)
        ai_json = _fallback_ai_report(structured_data)
        ai_json["report_source_reason"] = "openai_request_failed"

    with output.open("w", encoding="utf-8") as file:
        json.dump(ai_json, file, indent=2)
    return ai_json
