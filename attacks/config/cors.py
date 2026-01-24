import requests


def test_cors(host):
    findings = []

    headers = {
        "Origin": "https://evil.com",
        "User-Agent": "SentinelX"
    }

    try:
        r = requests.get(host, headers=headers, timeout=8)

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acc = r.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acc.lower() == "true":
            findings.append({
                "phase": 5,
                "type": "CORS Misconfiguration",
                "url": host,
                "evidence": "Wildcard origin with credentials",
                "severity": "High"
            })

        elif "evil.com" in acao:
            findings.append({
                "phase": 5,
                "type": "CORS Misconfiguration",
                "url": host,
                "evidence": "Origin reflected in ACAO header",
                "severity": "High"
            })

    except Exception:
        pass

    return findings
