import requests

METHODS = ["PUT", "DELETE", "PATCH"]


def test_http_methods(url):
    findings = []

    for m in METHODS:
        try:
            r = requests.request(
                m,
                url,
                timeout=8,
                headers={"User-Agent": "SentinelX"}
            )

            if r.status_code not in [401, 403, 405]:
                findings.append({
                    "phase": 3,
                    "type": "Insecure HTTP Method",
                    "url": url,
                    "method": m,
                    "status": r.status_code,
                    "severity": "Medium"
                })

        except:
            pass

    return findings
