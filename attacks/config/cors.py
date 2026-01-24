import requests
from auth.session import AUTH_HEADERS


def test_cors(host):
    findings = []

    headers = {
        **AUTH_HEADERS,
        "Origin": "https://evil.com"
    }

    try:
        r = requests.get(
            host,
            headers=headers,
            timeout=10
        )

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acc = r.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acc.lower() == "true":
            findings.append({
                "phase": 5,
                "type": "CORS Misconfiguration",
                "url": host,
                "evidence": "Wildcard ACAO with credentials",
                "severity": "High"
            })

        elif "evil.com" in acao:
            findings.append({
                "phase": 5,
                "type": "CORS Misconfiguration",
                "url": host,
                "evidence": "Origin reflection",
                "severity": "High"
            })

    except Exception:
        pass

    return findings
