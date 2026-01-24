import requests
import logging

logger = logging.getLogger("SentinelX")


def test_auth_bypass(endpoint, host):
    findings = []

    url = host + endpoint

    try:
        r = requests.get(url, timeout=10)

        if r.status_code == 200:
            findings.append({
                "type": "Missing Authentication",
                "endpoint": endpoint,
                "evidence": "Accessible without credentials"
            })

    except Exception:
        pass

    return findings
