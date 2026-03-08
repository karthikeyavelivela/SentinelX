"""Passive technology stack detection from HTTP responses and favicon hashing."""

from __future__ import annotations

import logging
import re
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)

# Extended signature dictionary — 40+ patterns
HEADER_SIGNATURES: dict[str, str] = {
    "cloudflare": "Cloudflare CDN",
    "x-cache": "Caching Layer (Varnish/CloudFront)",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-akamai": "Akamai CDN",
    "x-fastly": "Fastly CDN",
    "x-sucuri-id": "Sucuri WAF",
    "x-iinfo": "Imperva/Incapsula WAF",
}

SERVER_SIGNATURES: dict[str, str] = {
    "nginx": "Nginx",
    "apache": "Apache HTTP Server",
    "microsoft-iis": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "openresty": "OpenResty (Nginx+Lua)",
    "caddy": "Caddy",
    "gunicorn": "Gunicorn (Python)",
    "uvicorn": "Uvicorn (Python/ASGI)",
    "iis": "Microsoft IIS",
    "node": "Node.js",
    "kestrel": "ASP.NET Kestrel",
    "jetty": "Eclipse Jetty",
    "tomcat": "Apache Tomcat",
}

HTML_SIGNATURES: dict[str, str] = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "drupal.settings": "Drupal",
    "shopify": "Shopify",
    "magento": "Magento",
    "/cdn-cgi/": "Cloudflare",
    "__nuxt": "Nuxt.js (Vue.js SSR)",
    "_next/": "Next.js (React SSR)",
    "gatsby": "Gatsby (React)",
    "react": "React",
    "vue.js": "Vue.js",
    "angular": "Angular",
    "ember": "Ember.js",
    "svelte": "Svelte",
    "bootstrap": "Bootstrap",
    "tailwind": "Tailwind CSS",
    "jquery": "jQuery",
    "laravel": "Laravel (PHP)",
    "symfony": "Symfony (PHP)",
    "django": "Django (Python)",
    "rails": "Ruby on Rails",
    "jinja2": "Jinja2 / Python Web",
    "express": "Express.js",
    "fastapi": "FastAPI (Python)",
    "ghost": "Ghost CMS",
    "wix.com": "Wix",
    "squarespace": "Squarespace",
    "webflow": "Webflow",
    "hubspot": "HubSpot CMS",
    "elementor": "WordPress + Elementor",
    "woocommerce": "WooCommerce",
    "opencart": "OpenCart",
    "prestashop": "PrestaShop",
}


def detect_tech_stack(
    domain: str,
    timeout: int = 10,
    favicon_fingerprint: dict[str, Any] | None = None,
) -> list[str]:
    """Infer technologies from response headers, page source, and favicon hash."""
    detected: set[str] = set()
    url = f"https://{domain}"

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        html = response.text.lower()

        # Server header
        server = headers.get("server", "")
        if server:
            detected.add(f"Server: {response.headers.get('server', server)}")
            for sig, label in SERVER_SIGNATURES.items():
                if sig in server:
                    detected.add(label)

        # X-Powered-By
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            detected.add(f"X-Powered-By: {response.headers.get('x-powered-by', powered_by)}")

        # Generator meta tag
        generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html)
        if generator:
            detected.add(f"Generator: {generator.group(1).strip()}")

        # CDN/WAF headers
        for header_key, label in HEADER_SIGNATURES.items():
            if header_key in headers:
                detected.add(label)

        # HTML content signatures
        for needle, label in HTML_SIGNATURES.items():
            if needle in html:
                detected.add(label)

    except Exception as exc:
        LOGGER.warning("Tech stack detection failed for %s: %s", domain, exc)

    # Favicon fingerprint injection
    if favicon_fingerprint and favicon_fingerprint.get("technology"):
        detected.add(f"Favicon Match: {favicon_fingerprint['technology']}")

    return sorted(detected)
