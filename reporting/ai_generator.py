"""AI report generation — consulting-grade format with OWASP, attack paths, tech-specific remediation."""

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
    "report for executive stakeholders and engineering teams. Your analysis is precise, "
    "business-aware, and grounded in observable evidence. Avoid fear-based or alarmist language. "
    "Write with the confidence of a seasoned practitioner. Each finding must have a UNIQUE, "
    "finding-specific threat scenario — never a generic OSINT paragraph. Remediation must be "
    "conditioned on the detected technology stack where applicable."
)

USER_PROMPT_TEMPLATE = """\
You are generating a premium External Exposure Intelligence Report from passive scan data.

Return STRICT JSON only. No markdown, no prose, no explanations outside the JSON object.

JSON format:
{{
  "ExecutiveSummary": {{
    "OverallPosture": "<1–2 sentence characterisation of the organisation's external exposure posture>",
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
      "OWASPCategory": "<Most applicable OWASP Top 10 2021 category, e.g. A05:2021 – Security Misconfiguration>",
      "LikelyThreatScenario": "<UNIQUE, finding-specific attack chain — describe the EXACT steps an adversary takes for THIS specific finding. Never use generic OSINT language.>",
      "AttackPath": [
        "<Step 1: The initial condition or entry point>",
        "<Step 2: Adversary action enabled by the finding>",
        "<Step 3: Intermediate compromise or pivot>",
        "<Step 4: Escalation or propagation>",
        "<Step 5: Business impact — data breach, service disruption, account takeover, etc.>"
      ],
      "TechStackRemediation": "<Specific remediation steps conditioned on the detected technology stack. If WordPress, reference wp-config.php or .htaccess. If Nginx, reference nginx.conf directives. If CloudFlare, reference Transform Rules. Always be stack-specific.>",
      "RemediationRecommendation": "<Specific, step-level remediation action — never generic>",
      "RiskCategory": "High|Medium|Low"
    }}
  ],
  "OverallRisk": "High|Medium|Low"
}}

IMPORTANT RULES:
- Include only findings directly evidenced by the scan data.
- LikelyThreatScenario MUST be UNIQUE per finding — tailored to the specific vulnerability, NOT a generic "attacker performs passive OSINT" paragraph.
- AttackPath MUST be a JSON array of exactly 5 ordered strings forming a cause-to-impact chain.
- OWASPCategory MUST reference the OWASP Top 10 2021 list (A01–A10).
- TechStackRemediation MUST reference the specific technologies found in the scan (see tech_stack in the data).
- RemediationRecommendation must include concrete configuration values (e.g., header names, config file paths, firewall rule syntax).
- If a BusinessImpact sub-category is not relevant, write "Not directly applicable."
- OverallRisk must reflect the severity distribution of findings.

Structured Scan Data:
{structured_json}
"""


# ---------------------------------------------------------------------------
# Technology-Specific Remediation Templates
# ---------------------------------------------------------------------------

TECH_REMEDIATION_HINTS: dict[str, dict[str, str]] = {
    "nginx": {
        "hsts": (
            "In nginx.conf (server block): add_header Strict-Transport-Security "
            "'max-age=31536000; includeSubDomains; preload' always;"
        ),
        "csp": (
            "In nginx.conf: add_header Content-Security-Policy "
            "\"default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; object-src 'none';\" always;"
        ),
        "x-frame-options": "In nginx.conf: add_header X-Frame-Options DENY always;",
    },
    "apache": {
        "hsts": (
            "In .htaccess or apache2.conf: Header always set "
            "Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'"
        ),
        "csp": (
            "In .htaccess: Header always set Content-Security-Policy "
            "\"default-src 'self'; script-src 'self'; object-src 'none'\""
        ),
        "x-frame-options": "In .htaccess: Header always set X-Frame-Options DENY",
    },
    "cloudflare": {
        "hsts": (
            "In Cloudflare Dashboard → SSL/TLS → Edge Certificates → "
            "Enable HSTS with max-age=31536000 and includeSubDomains."
        ),
        "csp": (
            "In Cloudflare Dashboard → Rules → Transform Rules → "
            "HTTP Response Header Modification: Add Content-Security-Policy header."
        ),
    },
    "wordpress": {
        "hsts": (
            "Add to wp-config.php: define('FORCE_SSL_ADMIN', true); and set the HSTS header "
            "via your web server config or a security plugin such as Wordfence or iThemes Security."
        ),
        "default": (
            "Use the Wordfence or Solid Security plugin to enforce security headers. "
            "Ensure WordPress core, themes, and plugins are on the latest versions."
        ),
    },
    "iis": {
        "hsts": (
            "In IIS Manager → Site → HTTP Response Headers → Add: "
            "Name=Strict-Transport-Security, Value=max-age=31536000;includeSubDomains"
        ),
        "x-frame-options": "In web.config: <add name='X-Frame-Options' value='DENY' />",
    },
}


def _get_tech_remediation_hint(issue_text: str, tech_stack: list[str]) -> str:
    """Return a technology-specific remediation hint based on detected stack."""
    issue_lower = issue_text.lower()
    stack_lower = [t.lower() for t in tech_stack]

    for tech_key, remediation_map in TECH_REMEDIATION_HINTS.items():
        if any(tech_key in t for t in stack_lower):
            for hint_key, hint_text in remediation_map.items():
                if hint_key in issue_lower:
                    return hint_text
            if "default" in remediation_map:
                return remediation_map["default"]

    return ""


# ---------------------------------------------------------------------------
# Internal Fallback Generator
# ---------------------------------------------------------------------------

FALLBACK_REMEDIATION_MAP: dict[str, str] = {
    "expired ssl": (
        "Immediately renew the TLS certificate via your Certificate Authority or via Let's Encrypt. "
        "Configure automated ACME renewal (e.g., Certbot with --deploy-hook) to prevent recurrence. "
        "Verify renewal with: openssl s_client -connect {domain}:443 -servername {domain} | "
        "openssl x509 -noout -dates"
    ),
    "hsts": (
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all "
        "HTTPS responses. Submit the domain to the HSTS preload list at hstspreload.org once confirmed stable."
    ),
    "content-security-policy": (
        "Define and deploy a Content-Security-Policy header restricting trusted script, style, and media "
        "origins. Start in report-only mode using Content-Security-Policy-Report-Only with a report-uri "
        "endpoint to capture violations before enforcing."
    ),
    "x-frame-options": (
        "Add 'X-Frame-Options: DENY' to all HTTP responses, or use the Content-Security-Policy "
        "frame-ancestors directive: frame-ancestors 'none'. Validate using: curl -I https://{domain} | grep -i frame"
    ),
    "x-content-type": (
        "Add 'X-Content-Type-Options: nosniff' to all HTTP responses to prevent MIME-type sniffing attacks."
    ),
    "referrer-policy": (
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' to all responses to prevent "
        "sensitive URL fragment leakage via the Referer header."
    ),
    "port 21": (
        "Disable FTP (port 21) immediately unless operationally critical. If required: restrict via "
        "firewall/security group to authorised IPs only; disable anonymous authentication; "
        "migrate to SFTP (SSH/port 22) or FTPS."
    ),
    "port 22": (
        "Restrict SSH (port 22) to known IP ranges via firewall or security group rules. "
        "Disable password-based authentication: PasswordAuthentication no in /etc/ssh/sshd_config. "
        "Enforce key-based login only. Consider port-knocking or a bastion host."
    ),
    "port 3389": (
        "Remove RDP (port 3389) from public internet exposure immediately. Place behind a VPN or "
        "bastion host with MFA enforced. Enable Network Level Authentication (NLA). "
        "Apply Windows Firewall rules restricting source IPs."
    ),
    "port 3306": (
        "Remove MySQL (port 3306) from public internet exposure. Bind MySQL to localhost or "
        "private network IPs in /etc/mysql/mysql.conf.d/mysqld.cnf: bind-address = 127.0.0.1. "
        "Restrict access to application servers via VPC/private subnet."
    ),
    "port 6379": (
        "Bind Redis to localhost or private network: change 'bind 0.0.0.0' to 'bind 127.0.0.1' in redis.conf. "
        "Enable requirepass authentication. Remove Redis from public network access via firewall rules."
    ),
    "staging": (
        "Place staging, development, and pre-production environments behind authentication (Basic Auth, "
        "OAuth, or IP allow-list). Do not expose staging to the public internet. Use VPN-only access."
    ),
    "admin": (
        "Restrict administrative interfaces to internal networks or VPN access only. "
        "Apply MFA to all admin panel entry points. Implement rate-limiting on login endpoints."
    ),
    "technology": (
        "Suppress version-revealing response headers (Server, X-Powered-By, X-Generator). "
        "In Nginx: server_tokens off; In Apache: ServerTokens Prod; ServerSignature Off. "
        "Ensure all detected frameworks are on current stable versions."
    ),
    "subdomain": (
        "Conduct a full subdomain audit. Decommission unused subdomains by removing DNS records. "
        "Ensure all resolvable subdomains enforce authentication where applicable. "
        "Implement wildcard TLS certificates to prevent certificate transparency-based enumeration."
    ),
}

FALLBACK_THREAT_SCENARIOS: dict[str, str] = {
    "hsts": (
        "An adversary positioned on the same network segment as a target user (hotel Wi-Fi, "
        "conference network) initiates an SSL Strip attack using a tool such as sslstrip. "
        "Because HSTS is absent, the victim's browser accepts an unencrypted HTTP connection. "
        "The attacker captures the session cookie from the HTTP request and replays it against "
        "the application's authenticated API, achieving full account access."
    ),
    "content-security-policy": (
        "An attacker identifies a stored or reflected XSS vulnerability in a user-generated content "
        "field. Without a Content-Security-Policy, the injected <script> tag executes freely in the "
        "victim's browser. The script silently exfiltrates the session token via an attacker-controlled "
        "endpoint, granting authenticated access without any user interaction."
    ),
    "x-frame-options": (
        "The attacker creates a phishing page that embeds the target application's authenticated "
        "payment or account page inside a transparent iFrame. An overlay UI is rendered on top, "
        "tricking the authenticated user into clicking a button that triggers a funds transfer or "
        "account modification action on the embedded page — with no visible indication of deception."
    ),
    "ssl": (
        "The expired certificate causes end-users to receive browser security warnings. "
        "An attacker registers a look-alike domain with a valid certificate and redirects "
        "traffic via a targeted phishing campaign. Users who ignored the original certificate "
        "warning are conditioned to proceed — making them highly susceptible to the phishing "
        "redirect which harvests credentials at scale."
    ),
    "port 3389": (
        "Automated scanning infrastructure identifies the RDP service within seconds of internet "
        "exposure. A credential stuffing tool replays a list of 50,000 leaked username/password "
        "pairs. A valid Active Directory credential is found. The attacker establishes an RDP "
        "session, disables antivirus, drops a ransomware payload, and encrypts all accessible "
        "network shares within 4 hours."
    ),
    "port 22": (
        "A passive scan identifies the SSH service version, which is matched to a known CVE with a "
        "public exploit. Alternatively, the attacker performs a targeted credential brute-force using "
        "company-specific wordlists derived from LinkedIn employee enumeration. A valid credential "
        "is discovered, providing shell access. The attacker establishes an SSH tunnel for persistent "
        "access and begins lateral movement to adjacent internal systems."
    ),
    "port 3306": (
        "The public MySQL port is discovered via passive port enumeration. The attacker attempts "
        "authentication using default credentials (root/blank, root/root) and known credential "
        "pairs from public breach databases. Upon success, all database schemas are enumerated, "
        "customer PII and hashed credentials are extracted, and the attacker plants a UDF "
        "(User Defined Function) backdoor for persistent operating system access."
    ),
    "staging": (
        "The staging environment is indexed by search engines or discovered via certificate "
        "transparency logs. The attacker accesses it directly, finding debug endpoints, "
        "verbose error messages, and hardcoded test API keys. These keys are valid in production. "
        "The attacker uses the production API key to make authenticated API calls, "
        "exfiltrating customer data without triggering any authentication alerts."
    ),
    "admin": (
        "The public administrative interface is discovered via subdomain enumeration. The attacker "
        "attempts credential stuffing using the top 1,000 leaked admin credentials. When MFA is "
        "absent, a valid credential provides full administrative access. The attacker creates a "
        "backdoor admin account, exfiltrates the user database, and modifies application settings."
    ),
    "technology": (
        "The detected framework version is cross-referenced with CVE databases, revealing a known "
        "Remote Code Execution vulnerability. The attacker downloads a public proof-of-concept and "
        "validates it against the target without triggering any security alerts. A reverse shell is "
        "established, granting operating system level access to the application server and all "
        "data it can reach."
    ),
    "subdomain": (
        "The high-risk subdomain (dev/staging/api) is accessed directly. The subdomain serves an "
        "internal API with CORS set to allow-all and no authentication requirement. The attacker "
        "maps the full internal API surface, discovers an unauthenticated endpoint that returns "
        "customer records, and exfiltrates 50,000 records before the exposure is discovered."
    ),
}

FALLBACK_ATTACK_PATHS: dict[str, list[str]] = {
    "hsts": [
        "Missing HSTS Header Identified",
        "SSL Strip Attack Initiated on Shared Network",
        "Session Cookie Captured over Unencrypted HTTP",
        "Authenticated Session Replayed by Attacker",
        "Full Account Takeover — User Data and Transactions Accessible",
    ],
    "content-security-policy": [
        "Missing Content-Security-Policy",
        "XSS Payload Injected via User Input Field",
        "Malicious Script Executes in Victim Browser",
        "Session Token / Credential Exfiltrated to Attacker Server",
        "Account Compromised — Persistent Attacker Access",
    ],
    "x-frame-options": [
        "Missing X-Frame-Options Protection",
        "Application Embedded in Attacker-Controlled iFrame",
        "Clickjacking Overlay UI Rendered to Victim",
        "Victim Performs Authenticated Action Unknowingly",
        "Financial Transaction or Data Modification Executed",
    ],
    "ssl": [
        "Expired TLS Certificate Triggers Browser Warnings",
        "Users Conditioned to Accept Certificate Errors",
        "MITM Proxy Accepts Downgraded Connection",
        "Session Traffic Decrypted — Credentials Captured",
        "Customer Account Credentials Harvested at Scale",
    ],
    "port 3389": [
        "RDP Port 3389 Exposed to Public Internet",
        "Automated Scan Identifies and Targets Endpoint",
        "Credential Brute-Force or Stuffing Attack Succeeds",
        "Attacker Establishes Remote Desktop Session",
        "Ransomware Deployed — Full Infrastructure Encrypted",
    ],
    "port 22": [
        "SSH Port 22 Publicly Accessible",
        "Service Version Fingerprinted for Known CVEs",
        "Credential Attack or Exploit Executed",
        "Shell Access Obtained",
        "Data Exfiltration / Persistent Backdoor Installed",
    ],
    "port 3306": [
        "MySQL Port 3306 Exposed to Internet",
        "Default or Weak Credentials Attempted",
        "Database Authentication Bypassed",
        "Full Database Dump Executed",
        "Customer PII and Credentials Exfiltrated",
    ],
    "staging": [
        "Staging Environment Discovered via CT Logs",
        "Debug Endpoints and Test Credentials Found",
        "Production API Keys Extracted from Config",
        "Attacker Makes Authenticated Production API Calls",
        "Customer Data Exfiltrated Without Authentication Alert",
    ],
    "admin": [
        "Administrative Interface Exposed Without IP Restriction",
        "Login Endpoint Targeted by Credential Stuffing",
        "Valid Admin Credential Found",
        "Admin Access Gained — No MFA Protection",
        "User Database Exfiltrated / Backdoor Account Created",
    ],
    "technology": [
        "Technology Stack and Version Fingerprinted",
        "CVE Database Queried for Known Vulnerabilities",
        "Public Exploit Code Sourced and Weaponised",
        "Remote Code Execution Achieved",
        "Server Compromised — All Accessible Data at Risk",
    ],
}


def _build_fallback_finding(finding: dict | str, category: str, tech_stack: list[str]) -> dict[str, Any]:
    """Convert a risk finding dict into the premium finding schema."""
    # Support both old string format and new dict format
    if isinstance(finding, dict):
        issue = finding.get("text", "")
        owasp_code = finding.get("owasp_code", "A05")
        owasp_category = finding.get("owasp_category", "A05:2021 – Security Misconfiguration")
        prebuilt_path = finding.get("attack_path")
    else:
        issue = str(finding)
        owasp_code = "A05"
        owasp_category = "A05:2021 – Security Misconfiguration"
        prebuilt_path = None

    issue_lower = issue.lower()

    # Select best remediation
    remediation = "Review this finding with your infrastructure team and apply targeted hardening controls."
    for key, rec in FALLBACK_REMEDIATION_MAP.items():
        if key in issue_lower:
            remediation = rec
            break

    # Tech-specific override
    tech_hint = _get_tech_remediation_hint(issue, tech_stack)
    if tech_hint:
        remediation = f"{tech_hint}\n\nGeneral guidance: {remediation}"

    # Select best threat scenario
    threat_scenario = (
        "An adversary performing targeted reconnaissance identifies this condition and incorporates "
        "it into a structured attack plan, using it as an initial foothold for credential theft, "
        "data exfiltration, or further lateral movement."
    )
    for key, scenario in FALLBACK_THREAT_SCENARIOS.items():
        if key in issue_lower:
            threat_scenario = scenario
            break

    # Select attack path
    attack_path = prebuilt_path
    if not attack_path:
        for key, path in FALLBACK_ATTACK_PATHS.items():
            if key in issue_lower:
                attack_path = path
                break
        if not attack_path:
            attack_path = [
                "External Exposure Signal Identified",
                "Adversary Conducts Targeted Passive Reconnaissance",
                "Vulnerability Incorporated into Attack Plan",
                "Initial Access or Data Exfiltration Achieved",
                "Business Impact: Data Breach / Service Disruption / Credential Compromise",
            ]

    return {
        "Issue": issue[:120] if len(issue) > 120 else issue,
        "TechnicalDescription": issue,
        "SecurityImpact": (
            "This condition represents a validated passive indicator of external exposure. "
            "The specific impact depends on how an adversary leverages this signal."
        ),
        "BusinessImpact": {
            "DataExposureRisk": "Dependent on service exposed — evaluate data access scope.",
            "CredentialCompromiseRisk": "Possible if authentication interfaces or credentials are reachable.",
            "InfrastructureEnumerationRisk": "External adversaries can map service topology from observable signals.",
            "ComplianceRisk": "May constitute a control gap under SOC 2, PCI-DSS, or GDPR depending on data classification.",
            "ReputationRisk": "Publicly observable misconfigurations erode technical credibility with enterprise buyers.",
        },
        "OWASPCategory": owasp_category,
        "LikelyThreatScenario": threat_scenario,
        "AttackPath": attack_path,
        "TechStackRemediation": tech_hint or "Apply remediation according to your web server and framework documentation.",
        "RemediationRecommendation": remediation,
        "RiskCategory": category.capitalize(),
    }


def _fallback_ai_report(structured_data: dict[str, Any]) -> dict[str, Any]:
    """
    Generate a deterministic, structured fallback report when the AI service is unavailable.
    Never discloses the AI failure in the client-facing output.
    """
    risks = structured_data.get("risk_preliminary", {})
    tech_stack: list[str] = structured_data.get("tech_stack", [])
    findings: list[dict[str, Any]] = []

    for category in ("high", "medium", "low"):
        for item in risks.get(category, []):
            findings.append(_build_fallback_finding(item, category, tech_stack))

    overall = "High" if risks.get("high") else "Medium" if risks.get("medium") else "Low"

    domain = structured_data.get("domain", "the assessed domain")
    exposure_level = structured_data.get("exposure_level", overall)
    subdomain_count = len(structured_data.get("subdomains", []))

    high_items = risks.get("high", [])
    medium_items = risks.get("medium", [])
    high_count = len(high_items)
    medium_count = len(medium_items)

    def _text(item: dict | str) -> str:
        return item.get("text", str(item)) if isinstance(item, dict) else str(item)

    if high_count:
        top_risk_one = _text(high_items[0])
        top_risk_two = _text(high_items[1]) if len(high_items) > 1 else (
            _text(medium_items[0]) if medium_items else "Expand passive monitoring coverage"
        )
    elif medium_count:
        top_risk_one = _text(medium_items[0])
        top_risk_two = _text(medium_items[1]) if medium_count > 1 else "Expand passive monitoring coverage"
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
                "Schedule a follow-up passive assessment in 90 days to validate posture improvement."
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
        # Strip markdown code fences if present
        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
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
