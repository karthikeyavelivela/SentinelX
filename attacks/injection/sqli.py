import requests
from auth.session import AUTH_HEADERS

SQL_PAYLOADS = [
    "'",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 'a'='a",
    "') OR ('1'='1"
]

SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "psql",
    "sqlite",
    "ora-",
    "syntax error",
    "unclosed quotation",
    "query failed"
]


def test_sqli(url):
    findings = []

    if "?" not in url:
        return findings

    for payload in SQL_PAYLOADS:
        test_url = url + payload

        try:
            r = requests.get(
                test_url,
                headers=AUTH_HEADERS,
                timeout=10
            )

            body = r.text.lower()

            for err in SQL_ERRORS:
                if err in body:
                    findings.append({
                        "phase": 4,
                        "type": "SQL Injection (error-based)",
                        "url": test_url,
                        "evidence": err,
                        "severity": "Critical"
                    })
                    return findings

        except Exception:
            pass

    return findings
