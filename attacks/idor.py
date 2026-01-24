import requests
import logging
import re

logger = logging.getLogger("SentinelX")


def test_idor(url):
    """
    Safe IDOR detection using numeric object substitution.
    No data extraction performed.
    """

    findings = []

    # Only test URLs containing numeric IDs
    if not re.search(r"/\d+", url):
        return findings

    test_ids = ["1", "2", "3"]

    for tid in test_ids:
        test_url = re.sub(r"/\d+", f"/{tid}", url)

        try:
            r = requests.get(
                test_url,
                timeout=8,
                headers={"User-Agent": "SentinelX"}
            )

            if r.status_code == 200 and len(r.text) > 20:
                findings.append({
                    "type": "IDOR",
                    "url": test_url,
                    "evidence": f"Object ID {tid} accessible",
                    "severity": "High"
                })

        except Exception:
            continue

    return findings
