import requests
from auth.session import AUTH_HEADERS

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]


def test_security_headers(host):
    findings = []

    try:
        r = requests.get(
            host,
            headers=AUTH_HEADERS,
            timeout=10
        )

        missing = [
            h for h in SECURITY_HEADERS
            if h not in r.headers
        ]

        if missing:
            findings.append({
                "phase": 5,
                "type": "Missing Security Headers",
                "url": host,
                "missing": missing,
                "severity": "Low"
            })

    except Exception:
        pass

    return findings
