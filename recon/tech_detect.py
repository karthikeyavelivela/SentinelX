import requests
import logging

logger = logging.getLogger("SentinelX")

def detect_tech(url):
    technologies = []

    try:
        r = requests.get(url, timeout=5)

        headers = r.headers

        if "server" in headers:
            technologies.append(headers["server"])

        if "x-powered-by" in headers:
            technologies.append(headers["x-powered-by"])

    except Exception as e:
        logger.error(f"Tech detection failed for {url}")

    return technologies
