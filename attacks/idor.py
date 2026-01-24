import re
import requests
import logging
from auth.session import AUTH_HEADERS

logger = logging.getLogger("SentinelX")


def test_idor(url):
    """
    Safe IDOR detection using numeric object substitution.
    Uses authenticated session if available.
    """

    findings = []

    # must contain numeric object reference
    match = re.search(r"/(\d+)", url)
    if not match:
        return findings

    original_id = match.group(1)

    test_ids = ["1", "2", "3", "4"]

    for tid in test_ids:
        if tid == original_id:
            continue

        test_url = url.replace(original_id, tid)

        try:
            r = requests.get(
                test_url,
                headers=AUTH_HEADERS,
                timeout=10
            )

            body = r.text.lower()

            if (
                r.status_code == 200
                and "unauthorized" not in body
                and "forbidden" not in body
                and "not authorized" not in body
            ):
                findings.append({
                    "phase": 3,
                    "type": "IDOR",
                    "url": test_url,
                    "evidence": f"Object ID changed {original_id} → {tid}",
                    "severity": "High"
                })
                break

        except Exception as e:
            continue

    return findings
