"""Passive technology stack detection from HTTP responses."""

from __future__ import annotations

import logging
import re

import requests

LOGGER = logging.getLogger(__name__)

SIGNATURES = {
    "cloudflare": "Cloudflare",
    "wp-content": "WordPress",
    "drupal.settings": "Drupal",
    "shopify": "Shopify",
    "react": "React",
    "vue": "Vue.js",
    "angular": "Angular",
    "bootstrap": "Bootstrap",
}


def detect_tech_stack(domain: str, timeout: int = 10) -> list[str]:
    """Infer technologies by checking response headers and page source patterns."""
    detected: set[str] = set()
    url = f"https://{domain}"
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        html = response.text.lower()

        if headers.get("server"):
            detected.add(f"Server: {headers['server']}")
        if headers.get("x-powered-by"):
            detected.add(f"X-Powered-By: {headers['x-powered-by']}")

        generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html)
        if generator:
            detected.add(f"Generator: {generator.group(1)}")

        for needle, label in SIGNATURES.items():
            if needle in html or needle in str(headers).lower():
                detected.add(label)
    except Exception as exc:
        LOGGER.warning("Tech stack detection failed for %s: %s", domain, exc)

    return sorted(detected)

