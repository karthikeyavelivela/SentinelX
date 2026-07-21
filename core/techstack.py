"""Passive technology stack detection from scored HTTP signatures and favicon hashing."""

from __future__ import annotations

import logging
import re
from typing import Any

from core.http_utils import get_with_retries

LOGGER = logging.getLogger(__name__)

SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "WordPress",
        "patterns": [("html", "wp-content"), ("html", "wp-includes"), ("generator", "wordpress")],
        "min_matches": 2,
        "confidence": "high",
    },
    {
        "name": "React",
        "patterns": [("html", "data-reactroot"), ("html", "__react"), ("html", "react")],
        "min_matches": 2,
        "confidence": "medium",
    },
    {
        "name": "Vue",
        "patterns": [("html", "__vue"), ("html", "vue.js"), ("html", "data-v-")],
        "min_matches": 2,
        "confidence": "medium",
    },
    {
        "name": "Angular",
        "patterns": [("html", "ng-version"), ("html", "angular"), ("html", "ng-app")],
        "min_matches": 2,
        "confidence": "medium",
    },
    {
        "name": "Django",
        "patterns": [("headers", "csrftoken"), ("html", "csrfmiddlewaretoken"), ("html", "__admin_media_prefix__")],
        "min_matches": 1,
        "confidence": "medium",
    },
    {
        "name": "Laravel",
        "patterns": [("headers", "laravel_session"), ("headers", "x-powered-by: php"), ("html", "laravel")],
        "min_matches": 2,
        "confidence": "medium",
    },
    {
        "name": "Next.js",
        "patterns": [("html", "_next/"), ("html", "__next"), ("headers", "x-powered-by: next.js")],
        "min_matches": 2,
        "confidence": "high",
    },
    {
        "name": "Nginx",
        "patterns": [("server", "nginx"), ("headers", "server: nginx")],
        "min_matches": 1,
        "confidence": "high",
    },
    {
        "name": "Apache",
        "patterns": [("server", "apache"), ("headers", "server: apache")],
        "min_matches": 1,
        "confidence": "high",
    },
    {
        "name": "Cloudflare",
        "patterns": [("headers", "cf-ray"), ("headers", "server: cloudflare"), ("html", "/cdn-cgi/")],
        "min_matches": 2,
        "confidence": "high",
    },
    {
        "name": "AWS",
        "patterns": [("headers", "x-amz-cf-id"), ("headers", "x-amz-cf-pop"), ("headers", "server: amazons3")],
        "min_matches": 1,
        "confidence": "medium",
    },
    {
        "name": "Vercel",
        "patterns": [("headers", "x-vercel-id"), ("headers", "server: vercel"), ("html", "_vercel")],
        "min_matches": 1,
        "confidence": "high",
    },
    {
        "name": "jQuery",
        "patterns": [("html", "jquery"), ("html", "$("), ("html", "jquery.min.js")],
        "min_matches": 2,
        "confidence": "medium",
    },
    {
        "name": "Bootstrap",
        "patterns": [("html", "bootstrap.min.css"), ("html", "bootstrap.min.js"), ("html", "class=\"container")],
        "min_matches": 2,
        "confidence": "medium",
    },
]


def _generator_content(html: str) -> str:
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html)
    return generator.group(1).strip().lower() if generator else ""


def _signature_matches(
    signature: dict[str, Any],
    *,
    server: str,
    headers_text: str,
    html: str,
    generator: str,
) -> list[str]:
    matched: list[str] = []
    for source, needle in signature["patterns"]:
        haystack = (
            server
            if source == "server"
            else headers_text
            if source == "headers"
            else generator
            if source == "generator"
            else html
        )
        if needle.lower() in haystack:
            matched.append(needle)
    return matched


def detect_tech_stack(
    domain: str,
    *,
    timeout: int = 10,
    user_agent: str = "SentinelX/2.0 Security Audit Scanner",
    rate_limit_ms: int = 0,
    max_retries: int = 0,
    favicon_fingerprint: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Infer technologies from response headers, page source, and favicon hash."""
    detected: list[dict[str, Any]] = []
    url = f"https://{domain}"

    try:
        response = get_with_retries(
            url,
            timeout=timeout,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
        )
        headers = {key.lower(): value.lower() for key, value in response.headers.items()}
        html = response.text.lower()
        server = headers.get("server", "")
        generator = _generator_content(html)
        headers_text = "\n".join(f"{key}: {value}" for key, value in headers.items())
        powered_by = headers.get("x-powered-by", "")

        if server:
            detected.append(
                {
                    "name": f"Server Banner: {response.headers.get('server', server)}",
                    "confidence": "low",
                    "matched_patterns": ["server"],
                }
            )
        if powered_by:
            detected.append(
                {
                    "name": f"X-Powered-By: {response.headers.get('x-powered-by', powered_by)}",
                    "confidence": "low",
                    "matched_patterns": ["x-powered-by"],
                }
            )
        if generator:
            detected.append(
                {
                    "name": f"Generator: {generator}",
                    "confidence": "low",
                    "matched_patterns": ["generator"],
                }
            )

        for signature in SIGNATURES:
            matched = _signature_matches(
                signature,
                server=server,
                headers_text=headers_text,
                html=html,
                generator=generator,
            )
            if len(matched) >= int(signature["min_matches"]):
                detected.append(
                    {
                        "name": str(signature["name"]),
                        "confidence": str(signature["confidence"]),
                        "matched_patterns": matched,
                    }
                )
    except Exception as exc:
        LOGGER.warning("Tech stack detection failed for %s: %s", domain, exc)

    if favicon_fingerprint and favicon_fingerprint.get("technology"):
        detected.append(
            {
                "name": f"Favicon Match: {favicon_fingerprint['technology']}",
                "confidence": "medium",
                "matched_patterns": [str(favicon_fingerprint.get("hash"))],
            }
        )

    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for item in detected:
        key = (str(item["name"]), str(item["confidence"]))
        existing = unique.get(key)
        if existing:
            existing["matched_patterns"] = sorted(
                set(existing.get("matched_patterns", [])) | set(item.get("matched_patterns", []))
            )
        else:
            unique[key] = {
                "name": str(item["name"]),
                "confidence": str(item["confidence"]),
                "matched_patterns": sorted(set(item.get("matched_patterns", []))),
            }

    return sorted(unique.values(), key=lambda item: (item["name"], item["confidence"]))
