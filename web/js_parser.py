import re
import requests
import logging

logger = logging.getLogger("SentinelX")

# Very tolerant regex for modern frameworks
API_REGEX = re.compile(
    r"""
    ["'](
        \/
        (?:api|rest|v1|v2|v3|auth|user|admin|graphql)
        [^"'\\\s]{1,200}
    )["']
    """,
    re.VERBOSE | re.IGNORECASE
)


def extract_js_endpoints(js_url):
    endpoints = set()

    try:
        r = requests.get(
            js_url,
            timeout=10,
            headers={
                "User-Agent": "SentinelX",
                "Accept": "*/*"
            }
        )

        if r.status_code != 200:
            return []

        # prevent freezing on large bundles
        content = r.text[:2_000_000]

        matches = API_REGEX.findall(content)

        for m in matches:
            if m.startswith("/"):
                endpoints.add(m)

    except Exception:
        logger.debug(f"JS parse failed: {js_url}")

    return list(endpoints)
