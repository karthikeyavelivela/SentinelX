from risk.scorer import enrich_finding


def run_risk_engine(findings: list) -> list:
    enriched = []

    for finding in findings:
        # normalize schema
        finding.setdefault("phase", "unknown")
        finding.setdefault("severity", "Low")
        finding.setdefault("url", "N/A")
        finding.setdefault("evidence", "")
        finding.setdefault("type", "Unknown")

        try:
            enriched.append(enrich_finding(finding))
        except Exception:
            enriched.append(finding)

    return enriched
