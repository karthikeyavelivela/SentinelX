from attacks.config.cors import test_cors
from attacks.config.headers import test_security_headers
from attacks.config.debug import test_debug_pages
from attacks.config.methods import test_http_methods


def run_config_tests(endpoints):
    findings = []
    tested_hosts = set()

    for ep in endpoints:
        url = ep["url"]
        host = ep["host"]

        if host not in tested_hosts:
            findings.extend(test_cors(host))
            findings.extend(test_security_headers(host))
            tested_hosts.add(host)

        findings.extend(test_http_methods(url))
        findings.extend(test_debug_pages(url))

    return findings
