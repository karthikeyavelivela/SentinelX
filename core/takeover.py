"""Subdomain takeover heuristics for known dangling CNAME targets."""

from __future__ import annotations

import logging
from typing import Any

import dns.resolver

from core.http_utils import get_with_retries

LOGGER = logging.getLogger(__name__)

TAKEOVER_SERVICES: dict[str, dict[str, Any]] = {
    "unbouncepages.com": {
        "service": "Unbounce",
        "fingerprints": ["The requested URL was not found on this server"],
    },
    "github.io": {
        "service": "GitHub Pages",
        "fingerprints": ["There isn't a GitHub Pages site here", "Repository not found"],
    },
    "heroku.com": {
        "service": "Heroku",
        "fingerprints": ["No such app"],
    },
    "amazonaws.com": {
        "service": "Amazon S3",
        "fingerprints": ["The specified bucket does not exist"],
    },
    "azurewebsites.net": {
        "service": "Azure App Service",
        "fingerprints": ["404 Web Site not found"],
    },
    "cloudapp.net": {
        "service": "Azure CloudApp",
        "fingerprints": ["The resource you are looking for has been removed"],
    },
    "trafficmanager.net": {
        "service": "Azure Traffic Manager",
        "fingerprints": ["This Azure website is currently unavailable"],
    },
    "ghost.io": {
        "service": "Ghost",
        "fingerprints": ["The thing you were looking for is no longer here"],
    },
    "surge.sh": {
        "service": "Surge",
        "fingerprints": ["project not found"],
    },
    "bitbucket.io": {
        "service": "Bitbucket",
        "fingerprints": ["Repository not found"],
    },
    "helpjuice.com": {
        "service": "Helpjuice",
        "fingerprints": ["We could not find what you're looking for"],
    },
    "helpscoutdocs.com": {
        "service": "Help Scout Docs",
        "fingerprints": ["No settings were found for this company"],
    },
    "cargo.site": {
        "service": "Cargo",
        "fingerprints": ["If you're moving your domain away from Cargo"],
    },
    "feedpress.me": {
        "service": "FeedPress",
        "fingerprints": ["The feed has not been found"],
    },
    "freshdesk.com": {
        "service": "Freshdesk",
        "fingerprints": ["Freshdesk Contact Center Login"],
    },
    "uservoice.com": {
        "service": "UserVoice",
        "fingerprints": ["This UserVoice subdomain is currently available"],
    },
}


def _make_resolver(timeout: int) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _resolve_cname_chain(host: str, resolver: dns.resolver.Resolver, max_depth: int = 5) -> list[str]:
    chain: list[str] = []
    current = host.rstrip(".")
    for _ in range(max_depth):
        try:
            answers = resolver.resolve(current, "CNAME")
        except Exception:
            break
        target = str(answers[0].target).rstrip(".")
        chain.append(target)
        current = target
    return chain


def _service_for_chain(chain: list[str]) -> dict[str, Any] | None:
    for target in chain:
        lowered = target.lower()
        for suffix, config in TAKEOVER_SERVICES.items():
            if lowered.endswith(suffix):
                return config
    return None


def detect_subdomain_takeovers(
    subdomains: list[str],
    *,
    dns_timeout: int,
    http_timeout: int,
    user_agent: str,
    rate_limit_ms: int,
    max_retries: int,
) -> list[dict[str, Any]]:
    """Flag likely dangling CNAMEs that match known takeover fingerprints."""
    resolver = _make_resolver(dns_timeout)
    findings: list[dict[str, Any]] = []

    for host in sorted(set(subdomains)):
        chain = _resolve_cname_chain(host, resolver)
        if not chain:
            continue

        service_config = _service_for_chain(chain)
        if not service_config:
            continue

        response_text = ""
        fingerprint_matched = ""
        confidence = "medium"

        for scheme in ("https", "http"):
            try:
                response = get_with_retries(
                    f"{scheme}://{host}",
                    timeout=http_timeout,
                    headers={"User-Agent": user_agent},
                    allow_redirects=True,
                    rate_limit_ms=rate_limit_ms,
                    max_retries=max_retries,
                )
                response_text = response.text[:2000]
                break
            except Exception as exc:
                LOGGER.debug("Takeover HTTP probe failed for %s over %s: %s", host, scheme, exc)

        for fingerprint in service_config["fingerprints"]:
            if fingerprint.lower() in response_text.lower():
                fingerprint_matched = fingerprint
                confidence = "high"
                break

        findings.append(
            {
                "subdomain": host,
                "cname_chain": chain,
                "service": str(service_config["service"]),
                "fingerprint_matched": fingerprint_matched or None,
                "confidence": confidence,
            }
        )

    return findings
