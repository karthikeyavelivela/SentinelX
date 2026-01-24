IMPACT_MAP = {
    "IDOR": "Unauthorized access to other users' data",
    "Authentication Bypass": "Unauthenticated access to protected resources",
    "Missing Authentication": "Unauthenticated access to protected resources",

    "SQL Injection (error-based)": "Potential database compromise",
    "Reflected XSS (possible)": "Client-side code execution risk",
    "Open Redirect": "Phishing and credential theft risk",

    "CORS Misconfiguration": "Cross-origin data exposure",
    "Missing Security Headers": "Reduced browser-side protection",
    "Insecure HTTP Method": "Unauthorized modification or deletion of resources",
    "Debug Information Exposure": "Internal application details disclosure"
}


def get_business_impact(vuln_type: str) -> str:
    return IMPACT_MAP.get(
        vuln_type,
        "Security weakness requiring further investigation"
    )
