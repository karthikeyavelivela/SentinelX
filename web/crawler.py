import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger("SentinelX")


def crawl_site(base_url, max_pages=30):
    visited = set()
    to_visit = [base_url]

    endpoints = set()
    js_files = set()

    domain = urlparse(base_url).netloc

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)

        if url in visited:
            continue

        visited.add(url)

        try:
            r = requests.get(url, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")

            # ---------------------------
            # Internal links
            # ---------------------------
            for tag in soup.find_all(["a", "form"]):
                link = tag.get("href") or tag.get("action")

                if not link:
                    continue

                full = urljoin(base_url, link)

                if urlparse(full).netloc == domain:
                    endpoints.add(urlparse(full).path)
                    to_visit.append(full)

            # ---------------------------
            # JS files
            # ---------------------------
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    js_files.add(urljoin(base_url, src))

        except Exception as e:
            logger.debug(f"Crawl error: {url}")

    return list(endpoints), list(js_files)
