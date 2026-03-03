"""AI report generation from structured scanner output — premium consultant-grade format."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

LOGGER = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a senior SaaS security consultant generating a paid external exposure intelligence "
    "report for executive stakeholders. Your analysis is precise, business-aware, and grounded "
    "in observable evidence. Avoid fear-based or alarmist language. Write with the confidence "
    "of a seasoned practitioner. Every finding must reflect a realistic, organisation-relevant "
    "threat scenario with specific, actionable remediation — never generic advice."
)

USER_PROMPT_TEMPLATE = """\
You are generating a premium External Exposure Intelligence Report from passive scan data.

Return STRICT JSON only. No markdown, no prose, no explanations outside the JSON object.

JSON format:
{{
  "ExecutiveSummary": {{
    "OverallPosture": "<1–2 sentence characterisation of the organisation's current external exposure posture>",
    "TopRiskOne": "<First primary risk — specific, business-framed>",
    "TopRiskTwo": "<Second primary risk — specific, business-framed>",
    "RecommendedNextStep": "<Single highest-value remediation action>",
    "PassiveAssessmentStatement": "This assessment relied exclusively on passive, publicly observable signals. No intrusive testing, exploitation, or active probing was performed at any stage."
  }},
  "Findings": [
    {{
      "Issue": "<Short descriptive title>",
      "TechnicalDescription": "<Factual technical description of the observed condition>",
      "SecurityImpact": "<Direct security consequence if the condition is exploited>",
      "BusinessImpact": {{
        "DataExposureRisk": "<Risk to sensitive data or customer records>",
        "CredentialCompromiseRisk": "<Risk to credentials or authentication systems>",
        "InfrastructureEnumerationRisk": "<Risk of infrastructure mapping by adversaries>",
        "ComplianceRisk": "<Relevant regulatory or compliance exposure (PCI-DSS, SOC 2, GDPR, etc.)>",
        "ReputationRisk": "<Customer trust or public perception impact>"
      }},
      "LikelyThreatScenario": "<Concrete, realistic attack chain an adversary could follow>",
      "RemediationRecommendation": "<Specific, step-level remediation action — never generic>",
      "RiskCategory": "High|Medium|Low"
    }}
  ],
  "OverallRisk": "High|Medium|Low"
}}

IMPORTANT:
- Include only findings that are directly evidenced by the scan data.
- RemediationRecommendation must be specific (e.g., "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to your web server configuration" not "Apply standard hardening.").
- If a BusinessImpact sub-category is not relevant, write "Not directly applicable" rather than leaving it vague.
- OverallRisk must reflect the severity distribution of findings.

Structured Scan Data:
{structured_json}
"""


# ---------------------------------------------------------------------------
# Internal Summary Fallback
# ---------------------------------------------------------------------------

def _build_fallback_finding(issue: str, category: str) -> dict[str, Any]:
    """Convert a raw risk string into the premium finding schema."""
    cat_lower = category.lower()

    tech_desc = issue
    security_impact = (
        "This condition represents a validated passive indicator of external exposure. "
        "The specific impact depends on how this signal is leveraged by an adversary."
    )

    remediation_map: dict[str, str] = {
        "expired ssl": (
            "Immediately renew the TLS certificate via your Certificate Authority or a managed "
            "provider such as Let's Encrypt. Automate renewal using ACME to prevent recurrence."
        ),
        "hsts": (
            "Add the response header 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload' to all HTTPS responses via your web server or CDN configuration."
        ),
        "content-security-policy": (
            "Define and deploy a Content-Security-Policy header that restricts trusted script, "
            "style, and media origins. Use report-uri or report-to directives to monitor violations "
            "before enforcing."
        ),
        "x-frame-options": (
            "Add 'X-Frame-Options: DENY' (or SAMEORIGIN if embedding is required) to all HTTP "
            "responses. Alternatively use Content-Security-Policy's frame-ancestors directive."
        ),
        "port 21": (
            "Disable FTP (port 21) if not operationally required. If required, restrict access via "
            "firewall allow-list to known IPs only. Disable anonymous authentication."
        ),
        "port 22": (
            "Restrict SSH (port 22) access via firewall or security group rules to authorised "
            "source IPs exclusively. Disable password-based authentication; enforce key-based "
            "login only."
        ),
        "port 3389": (
            "Remove RDP (port 3389) from public internet exposure immediately. Place behind a VPN "
            "or bastion host with MFA. Apply Network Level Authentication."
        ),
        "port 3306": (
            "Remove MySQL (port 3306) from public internet exposure. Database access should be "
            "restricted to application servers via private networking only."
        ),
        "staging": (
            "Place staging, development, and pre-production environments behind authentication "
            "or IP restriction. Do not leave these environments publicly accessible."
        ),
        "admin": (
            "Restrict administrative interfaces to internal networks or VPN access only. "
            "Apply multi-factor authentication to all admin panel entry points."
        ),
    }

    remediation = "Review this finding with your infrastructure team and apply targeted hardening controls."
    for key, rec in remediation_map.items():
        if key in issue.lower():
            remediation = rec
            break

    return {
        "Issue": issue[:120] if len(issue) > 120 else issue,
        "TechnicalDescription": tech_desc,
        "SecurityImpact": security_impact,
        "BusinessImpact": {
            "DataExposureRisk": "Dependent on service exposed — evaluate data access scope.",
            "CredentialCompromiseRisk": "Possible if authentication interfaces or credentials are reachable.",
            "InfrastructureEnumerationRisk": "External adversaries can map service topology from observable signals.",
            "ComplianceRisk": "May constitute a control gap under SOC 2, PCI-DSS, or GDPR depending on data classification.",
            "ReputationRisk": "Publicly observable misconfigurations erode technical credibility with enterprise buyers.",
        },
        "LikelyThreatScenario": (
            "An adversary performing passive OSINT discovers this condition, incorporates it into "
            "a target dossier, and uses it to inform a targeted phishing, credential-stuffing, or "
            "direct intrusion attempt."
        ),
        "RemediationRecommendation": remediation,
        "RiskCategory": category.capitalize(),
    }


def _fallback_ai_report(structured_data: dict[str, Any]) -> dict[str, Any]:
    """
    Generate a deterministic, structured fallback report when the AI service is unavailable.
    Never discloses the AI failure in the client-facing output.
    """
    risks = structured_data.get("risk_preliminary", {})
    findings: list[dict[str, Any]] = []

    for category in ("high", "medium", "low"):
        for item in risks.get(category, []):
            findings.append(_build_fallback_finding(item, category))

    overall = "High" if risks.get("high") else "Medium" if risks.get("medium") else "Low"

    domain = structured_data.get("domain", "the assessed domain")
    exposure_level = structured_data.get("exposure_level", overall)
    subdomain_count = len(structured_data.get("subdomains", []))
    high_count = len(risks.get("high", []))
    medium_count = len(risks.get("medium", []))

    if high_count:
        top_risk_one = risks["high"][0]
        top_risk_two = risks["high"][1] if len(risks["high"]) > 1 else (risks["medium"][0] if risks.get("medium") else "Expand passive monitoring coverage")
    elif medium_count:
        top_risk_one = risks["medium"][0]
        top_risk_two = risks["medium"][1] if medium_count > 1 else "Expand passive monitoring coverage"
    else:
        top_risk_one = "No material risk indicators identified in current scan window"
        top_risk_two = "Establish a baseline monitoring cadence for change detection"

    return {
        "ExecutiveSummary": {
            "OverallPosture": (
                f"Passive external reconnaissance of {domain} identified a {exposure_level.lower()} "
                f"exposure posture across {subdomain_count} resolvable subdomain(s). "
                f"The assessment surfaced {high_count} high-severity and {medium_count} medium-severity "
                "indicators warranting structured remediation attention."
            ),
            "TopRiskOne": top_risk_one,
            "TopRiskTwo": top_risk_two,
            "RecommendedNextStep": (
                "Prioritise remediation of High-severity findings within the next 30 days. "
                "Schedule a follow-up passive assessment in 90 days to track posture improvement."
            ),
            "PassiveAssessmentStatement": (
                "This assessment relied exclusively on passive, publicly observable signals. "
                "No intrusive testing, exploitation, or active probing was performed at any stage."
            ),
        },
        "Findings": findings,
        "OverallRisk": overall,
    }


# ---------------------------------------------------------------------------
# Main Generator
# ---------------------------------------------------------------------------

def generate_ai_report(
    structured_input_path: str = "structured_output.json",
    output_path: str = "ai_report.json",
) -> dict[str, Any]:
    """Generate AI-enriched JSON report using gpt-4o-mini with graceful fallback."""
    LOGGER.info("Starting AI report generation from %s", structured_input_path)

    with open(structured_input_path, "r", encoding="utf-8") as file:
        structured_data = json.load(file)

    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        LOGGER.info("OPENAI_API_KEY not configured — using structured internal summary generator.")
        report = _fallback_ai_report(structured_data)
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
        LOGGER.info("AI report saved to %s (internal generator)", output_path)
        return report

    try:
        LOGGER.info("Requesting AI analysis via OpenAI API (gpt-4o-mini)")
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
        LOGGER.info("AI report successfully generated via OpenAI API.")

    except Exception as exc:
        LOGGER.warning("OpenAI generation failed — using structured internal summary: %s", exc)
        ai_json = _fallback_ai_report(structured_data)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(ai_json, file, indent=2)
    LOGGER.info("AI report saved to %s", output_path)
    return ai_json


def _extract_response_text(response: Any) -> str:
    """Extract text from OpenAI response object across SDK shapes."""
    if hasattr(response, "output_text") and response.output_text:
        return response.output_text
    if hasattr(response, "choices") and response.choices:
        return response.choices[0].message.content
    return str(response)
