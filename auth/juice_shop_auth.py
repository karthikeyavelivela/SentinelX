import requests
from auth.session import AUTH_HEADERS


def juice_shop_login(base_url):
    """
    Logs into OWASP Juice Shop and extracts JWT token.
    """

    login_url = f"{base_url}/rest/user/login"

    payload = {
        "email": "test@test.com",
        "password": "test123"
    }

    try:
        r = requests.post(
            login_url,
            json=payload,
            timeout=10
        )

        data = r.json()

        token = data.get("authentication", {}).get("token")

        if token:
            AUTH_HEADERS["Authorization"] = f"Bearer {token}"
            print("[+] Authenticated scan enabled (JWT acquired)")
            return True

    except Exception as e:
        print("[-] Authentication failed")

    return False
