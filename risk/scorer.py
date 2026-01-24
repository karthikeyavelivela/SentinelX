from risk.cvss import get_cvss_score
from risk.severity import cvss_to_severity
from risk.impact import get_business_impact


def enrich_finding(finding: dict) -> dict:
    vuln_type = finding.get("type", "Unknown")

    cvss = get_cvss_score(vuln_type)
    severity = cvss_to_severity(cvss)
    impact = get_business_impact(vuln_type)

    finding["cvss"] = cvss
    finding["severity"] = severity
    finding["business_impact"] = impact
    finding["confidence"] = "High"

    return finding
