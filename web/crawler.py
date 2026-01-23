import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger("SentinelX")


def crawl_site(base_url, max_pages=30):
    """
    Crawl website and extract internal URLs
    """

    logger.info(f"Crawling website: {base_url}")

    visited = set()
    to_visit = [base_url]
    endpoints = set()

    domain = urlparse(base_url).netloc

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)

        if url in visited:
            continue

        visited.add(url)

        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all(["a", "form"]):
                link = tag.get("href") or tag.get("action")
                if not link:
                    continue

                full_url = urljoin(base_url, link)
                parsed = urlparse(full_url)

                if parsed.netloc == domain:
                    endpoints.add(parsed.path)
                    to_visit.append(full_url)

        except Exception:
            continue

    logger.info(f"Crawler discovered {len(endpoints)} endpoints")
    return list(endpoints)
