CVSS_BASE_SCORES = {
    # Access control
    "IDOR": 9.1,
    "Authentication Bypass": 9.0,
    "Missing Authentication": 9.0,

    # Injection
    "SQL Injection (error-based)": 9.8,
    "Reflected XSS (possible)": 6.5,
    "Open Redirect": 6.1,

    # Misconfiguration
    "CORS Misconfiguration": 7.2,
    "Missing Security Headers": 4.0,
    "Insecure HTTP Method": 6.8,
    "Debug Information Exposure": 5.3,
}


def get_cvss_score(vuln_type: str) -> float:
    return CVSS_BASE_SCORES.get(vuln_type, 5.0)
