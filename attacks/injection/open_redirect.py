import requests
from urllib.parse import urlparse, parse_qs

REDIRECT_PARAMS = [
    "url", "next", "redirect",
    "return", "continue", "dest"
]


def test_open_redirect(url):
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param in REDIRECT_PARAMS:
        if param in params:
            test_url = url + "&" + param + "=https://example.com"

            try:
                r = requests.get(
                    test_url,
                    allow_redirects=False,
                    timeout=8,
                    headers={"User-Agent": "SentinelX"}
                )

                location = r.headers.get("Location", "")

                if (
                    r.status_code in [301, 302]
                    and "example.com" in location
                ):
                    findings.append({
                        "phase": 4,
                        "type": "Open Redirect",
                        "url": test_url,
                        "evidence": location,
                        "severity": "Medium"
                    })

            except Exception:
                pass

    return findings
