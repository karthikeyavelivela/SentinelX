import requests
from urllib.parse import urlparse, parse_qs
from auth.session import AUTH_HEADERS

REDIRECT_PARAMS = [
    "url", "next", "redirect",
    "return", "returnurl",
    "continue", "to", "dest"
]


def test_open_redirect(url):
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param in REDIRECT_PARAMS:
        if param not in params:
            continue

        test_url = (
            url + "&" + param + "=https://example.com"
        )

        try:
            r = requests.get(
                test_url,
                headers=AUTH_HEADERS,
                allow_redirects=False,
                timeout=10
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
