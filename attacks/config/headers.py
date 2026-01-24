import requests

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
            timeout=8,
            headers={"User-Agent": "SentinelX"}
        )

        missing = []

        for header in SECURITY_HEADERS:
            if header not in r.headers:
                missing.append(header)

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
