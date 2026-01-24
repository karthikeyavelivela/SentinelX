import requests

DANGEROUS_METHODS = ["PUT", "DELETE", "PATCH"]


def test_http_methods(url):
    findings = []

    for method in DANGEROUS_METHODS:
        try:
            r = requests.request(
                method,
                url,
                timeout=8,
                headers={"User-Agent": "SentinelX"},
                allow_redirects=False
            )

            if r.status_code not in [401, 403, 405]:
                findings.append({
                    "phase": 5,
                    "type": "Insecure HTTP Method",
                    "url": url,
                    "method": method,
                    "status": r.status_code,
                    "severity": "Medium"
                })

        except Exception:
            pass

    return findings
