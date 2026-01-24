from attacks.injection.sqli import test_sqli
from attacks.injection.xss import test_xss
from attacks.injection.open_redirect import test_open_redirect


def run_injection_tests(endpoints):
    findings = []

    for ep in endpoints:
        url = ep.get("url")

        if not url:
            continue

        findings.extend(test_sqli(url))
        findings.extend(test_xss(url))
        findings.extend(test_open_redirect(url))

    return findings
