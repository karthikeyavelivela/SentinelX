import re
import requests
import logging

logger = logging.getLogger("SentinelX")

API_REGEX = re.compile(
    r"""(?:"|')((?:/api|/v1|/v2|/v3)[^"' ]+)""",
    re.IGNORECASE
)


def extract_js_endpoints(js_url):
    endpoints = set()

    try:
        resp = requests.get(js_url, timeout=10)
        matches = API_REGEX.findall(resp.text)

        for m in matches:
            endpoints.add(m)

    except Exception:
        pass

    return list(endpoints)
