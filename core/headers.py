"""HTTP security headers inspection module."""

from __future__ import annotations

import logging
from typing import Any

from core.http_utils import get_with_retries

LOGGER = logging.getLogger(__name__)

HEADER_RULES: list[dict[str, str]] = [
    {
        "name": "strict-transport-security",
        "display": "Strict-Transport-Security",
        "recommendation": "Add HSTS with a long max-age and includeSubDomains once HTTPS is universal.",
    },
    {
        "name": "content-security-policy",
        "display": "Content-Security-Policy",
        "recommendation": "Define a restrictive CSP and remove unsafe-inline / unsafe-eval where possible.",
    },
    {
        "name": "x-content-type-options",
        "display": "X-Content-Type-Options",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    {
        "name": "x-frame-options",
        "display": "X-Frame-Options",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN unless framing is required.",
    },
    {
        "name": "referrer-policy",
        "display": "Referrer-Policy",
        "recommendation": "Use strict-origin-when-cross-origin or no-referrer.",
    },
    {
        "name": "permissions-policy",
        "display": "Permissions-Policy",
        "recommendation": "Explicitly disable unnecessary browser capabilities.",
    },
    {
        "name": "cross-origin-opener-policy",
        "display": "Cross-Origin-Opener-Policy",
        "recommendation": "Set Cross-Origin-Opener-Policy to same-origin for stronger isolation.",
    },
    {
        "name": "cross-origin-resource-policy",
        "display": "Cross-Origin-Resource-Policy",
        "recommendation": "Set Cross-Origin-Resource-Policy to same-site or same-origin where compatible.",
    },
    {
        "name": "x-dns-prefetch-control",
        "display": "X-DNS-Prefetch-Control",
        "recommendation": "Consider setting X-DNS-Prefetch-Control to off on sensitive applications.",
    },
]


def _evaluate_header(name: str, value: str | None) -> tuple[str, str]:
    if not value:
        return "FAIL", "Header is missing."

    lowered = value.lower()
    if name == "strict-transport-security":
        if "max-age=" not in lowered:
            return "WARN", "HSTS is present but max-age is missing."
        if "max-age=0" in lowered or "max-age=300" in lowered or "max-age=86400" in lowered:
            return "WARN", "HSTS is present but the max-age is short."
        if "includesubdomains" not in lowered:
            return "WARN", "HSTS is present but does not include subdomains."
        return "PASS", "HSTS is present with an acceptable enforcement pattern."
    if name == "content-security-policy":
        if "unsafe-inline" in lowered or "unsafe-eval" in lowered or "*" in lowered:
            return "WARN", "CSP is present but contains weak directives."
        return "PASS", "CSP is present and does not expose obvious weak directives."
    if name == "x-content-type-options":
        return ("PASS", "nosniff is enforced.") if lowered == "nosniff" else ("WARN", "Expected value is nosniff.")
    if name == "x-frame-options":
        return ("PASS", "Frame embedding is restricted.") if lowered in {"deny", "sameorigin"} else (
            "WARN",
            "Expected DENY or SAMEORIGIN.",
        )
    if name == "referrer-policy":
        if lowered in {"strict-origin-when-cross-origin", "no-referrer", "same-origin"}:
            return "PASS", "Referrer leakage is constrained."
        return "WARN", "Referrer-Policy is present but not strongly restrictive."
    if name == "permissions-policy":
        if "*" in lowered:
            return "WARN", "Permissions-Policy is present but still broadly permissive."
        return "PASS", "Permissions-Policy is present."
    if name == "cross-origin-opener-policy":
        return ("PASS", "Cross-origin opener isolation is enabled.") if lowered == "same-origin" else (
            "WARN",
            "Expected same-origin where application compatibility allows.",
        )
    if name == "cross-origin-resource-policy":
        return ("PASS", "Cross-origin resource access is restricted.") if lowered in {"same-origin", "same-site"} else (
            "WARN",
            "Expected same-origin or same-site where compatible.",
        )
    if name == "x-dns-prefetch-control":
        return ("PASS", "DNS prefetching is explicitly controlled.") if lowered == "off" else (
            "WARN",
            "Header is present but prefetching is not disabled.",
        )
    return "PASS", "Header is present."


def inspect_security_headers(
    domain: str,
    *,
    timeout: int = 10,
    user_agent: str = "SentinelX/2.0 Security Audit Scanner",
    rate_limit_ms: int = 0,
    max_retries: int = 0,
) -> dict[str, Any]:
    """Inspect publicly exposed HTTP response headers on the HTTPS endpoint."""
    target = f"https://{domain}"
    output: dict[str, Any] = {
        "target_url": target,
        "present": {},
        "missing": [],
        "headers": [],
        "error": None,
        "transport_ok": False,
        "status_summary": {"pass": 0, "warn": 0, "fail": 0, "unknown": 0},
    }

    try:
        response = get_with_retries(
            target,
            timeout=timeout,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
        )
        output["transport_ok"] = True
        headers = {key.lower(): value for key, value in response.headers.items()}
        for rule in HEADER_RULES:
            name = rule["name"]
            value = headers.get(name)
            status, note = _evaluate_header(name, value)
            if value:
                output["present"][name] = value
            else:
                output["missing"].append(name)
            output["headers"].append(
                {
                    "name": name,
                    "display_name": rule["display"],
                    "status": status,
                    "value": value or "",
                    "recommendation": rule["recommendation"],
                    "note": note,
                }
            )
            output["status_summary"][status.lower()] += 1
    except Exception as exc:
        LOGGER.warning("Header inspection failed for %s: %s", domain, exc)
        output["error"] = str(exc)
        for rule in HEADER_RULES:
            output["headers"].append(
                {
                    "name": rule["name"],
                    "display_name": rule["display"],
                    "status": "UNKNOWN",
                    "value": "",
                    "recommendation": rule["recommendation"],
                    "note": "Transport failure prevented header verification.",
                }
            )
        output["status_summary"]["unknown"] = len(HEADER_RULES)

    return output
