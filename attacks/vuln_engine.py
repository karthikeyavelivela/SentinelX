import logging
from attacks.idor import test_idor
from attacks.auth_bypass import test_auth_bypass
from attacks.method_tester import test_http_methods

logger = logging.getLogger("SentinelX")


def run_vulnerability_checks(endpoints):
    findings = []

    logger.info(f"Testing {len(endpoints)} endpoints")

    for ep in endpoints:
        url = ep.get("url")

        if not url:
            continue

        try:
            findings.extend(test_idor(url))
            findings.extend(test_auth_bypass(url))
            findings.extend(test_http_methods(url))

        except Exception as e:
            logger.debug(f"Phase 3 error {url}: {e}")

    return findings
