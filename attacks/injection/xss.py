import requests


def test_xss(url):
    findings = []

    if "?" not in url:
        return findings

    marker = "sentinelx_xss_test"

    test_url = url.replace("=", f"={marker}")

    try:
        r = requests.get(
            test_url,
            timeout=8,
            headers={"User-Agent": "SentinelX"}
        )

        if marker in r.text:
            findings.append({
                "phase": 4,
                "type": "Reflected XSS (possible)",
                "url": test_url,
                "evidence": "Input reflected in response",
                "severity": "Medium"
            })

    except Exception:
        pass

    return findings
