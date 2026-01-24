import requests
import logging

logger = logging.getLogger("SentinelX")

METHODS = ["PUT", "DELETE", "PATCH"]


def test_http_methods(url):
    """
    Tests dangerous HTTP methods on endpoints.
    """

    findings = []

    for method in METHODS:
        try:
            r = requests.request(
                method,
                url,
                timeout=8,
                headers={"User-Agent": "SentinelX"},
                allow_redirects=False
            )

            # Secure behavior
            if r.status_code in [401, 403, 405]:
                continue

            # Unexpected acceptance
            findings.append({
                "type": "Insecure HTTP Method",
                "url": url,
                "method": method,
                "status": r.status_code,
                "severity": "Medium"
            })

        except Exception:
            continue

    return findings
