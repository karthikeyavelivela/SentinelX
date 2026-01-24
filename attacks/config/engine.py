from attacks.config.cors import test_cors
from attacks.config.headers import test_security_headers
from attacks.config.methods import test_http_methods
from attacks.config.debug import test_debug_pages


def run_config_tests(endpoints):
    findings = []

    tested_hosts = set()

    for ep in endpoints:
        host = ep.get("host")
        url = ep.get("url")

        if not host or not url:
            continue

        # -----------------------
        # Host-level checks
        # -----------------------
        if host not in tested_hosts:
            findings.extend(test_cors(host))
            findings.extend(test_security_headers(host))
            tested_hosts.add(host)

        # -----------------------
        # Endpoint-level checks
        # -----------------------
        findings.extend(test_http_methods(url))
        findings.extend(test_debug_pages(url))

    return findings
