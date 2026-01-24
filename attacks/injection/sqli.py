import requests

SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "psql",
    "ora-",
    "syntax error",
    "unclosed quotation",
    "odbc",
    "sqlite"
]


def test_sqli(url):
    findings = []

    if "?" not in url:
        return findings

    test_url = url + "'"

    try:
        r = requests.get(
            test_url,
            timeout=8,
            headers={"User-Agent": "SentinelX"}
        )

        body = r.text.lower()

        for err in SQL_ERRORS:
            if err in body:
                findings.append({
                    "phase": 4,
                    "type": "SQL Injection (error-based)",
                    "url": test_url,
                    "evidence": err,
                    "severity": "High"
                })
                break

    except Exception:
        pass

    return findings
