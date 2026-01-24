import requests
from auth.session import AUTH_HEADERS

XSS_PAYLOAD = "<svg/onload=alert(1)>"


def test_xss(url):
    findings = []

    if "?" not in url:
        return findings

    test_url = url.replace("=", f"={XSS_PAYLOAD}")

    try:
        r = requests.get(
            test_url,
            headers=AUTH_HEADERS,
            timeout=10
        )

        if "<svg" in r.text.lower():
            findings.append({
                "phase": 4,
                "type": "Reflected XSS (possible)",
                "url": test_url,
                "evidence": "Payload reflected in response",
                "severity": "Medium"
            })

    except Exception:
        pass

    return findings
