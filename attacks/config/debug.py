import requests

DEBUG_SIGNS = [
    "traceback",
    "exception",
    "stack trace",
    "debug = true",
    "flask debugger",
    "django debug"
]


def test_debug_pages(url):
    findings = []

    try:
        r = requests.get(
            url,
            timeout=8,
            headers={"User-Agent": "SentinelX"}
        )

        body = r.text.lower()

        for sign in DEBUG_SIGNS:
            if sign in body:
                findings.append({
                    "phase": 5,
                    "type": "Debug Information Exposure",
                    "url": url,
                    "evidence": sign,
                    "severity": "Medium"
                })
                break

    except Exception:
        pass

    return findings
