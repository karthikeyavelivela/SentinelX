import subprocess
import logging
import requests

logger = logging.getLogger("SentinelX")


def enumerate_subdomains(domain):
    """
    Subdomain enumeration with fallback
    """

    logger.info("Starting subdomain enumeration")

    # -------------------------
    # Try subfinder first
    # -------------------------
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=30
        )

        subs = result.stdout.splitlines()
        if subs:
            logger.info(f"Found {len(subs)} subdomains using subfinder")
            return list(set(subs))

    except Exception:
        logger.warning("Subfinder not found — switching to passive method")

    # -------------------------
    # Passive fallback
    # -------------------------
    logger.info("Using passive certificate enumeration")

    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=15)

        if response.status_code == 200:
            data = response.json()

            for entry in data:
                name = entry.get("name_value")
                if name:
                    for sub in name.split("\n"):
                        if "*" not in sub:
                            subdomains.add(sub.strip())

    except Exception as e:
        logger.error(f"Passive enumeration failed: {e}")

    logger.info(f"Found {len(subdomains)} subdomains passively")
    return list(subdomains)
