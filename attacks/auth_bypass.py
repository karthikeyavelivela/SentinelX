import requests


def test_auth_bypass(url):
    findings = []

    try:
        r = requests.get(
            url,
            timeout=8,
            headers={"User-Agent": "SentinelX"}
        )

        body = r.text.lower()

        if (
            r.status_code == 200
            and "unauthorized" not in body
            and "forbidden" not in body
        ):
            findings.append({
                "phase": 3,
                "type": "Missing Authentication",
                "url": url,
                "evidence": "Accessible without authentication",
                "severity": "High"
            })

    except:
        pass

    return findings
