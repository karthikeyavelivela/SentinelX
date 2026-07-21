"""Passive subdomain enumeration utilities."""

from __future__ import annotations

import logging
from typing import Iterable, Set

import dns.resolver

from core.http_utils import get_with_retries

LOGGER = logging.getLogger(__name__)

COMMON_SUBDOMAIN_LABELS: tuple[str, ...] = (
    "www",
    "mail",
    "api",
    "app",
    "dev",
    "staging",
    "admin",
    "dashboard",
    "portal",
    "cdn",
    "assets",
    "static",
    "beta",
    "test",
    "uat",
    "preprod",
    "internal",
    "m",
    "blog",
    "docs",
    "status",
    "shop",
    "support",
    "help",
    "auth",
    "login",
    "sso",
    "gateway",
    "vpn",
    "remote",
    "files",
    "ftp",
    "ns1",
    "ns2",
    "smtp",
    "imap",
    "pop",
    "webmail",
    "mx",
    "payments",
    "billing",
    "erp",
    "crm",
    "api-dev",
    "api-staging",
    "stage",
    "sandbox",
    "demo",
    "secure",
    "media",
)


def _normalize_host(candidate: str, domain: str) -> str | None:
    hostname = candidate.strip().lower().rstrip(".")
    hostname = hostname.lstrip("*.").replace("..", ".")
    if not hostname:
        return None
    if hostname == domain or hostname.endswith(f".{domain}"):
        return hostname
    return None


def _fetch_crtsh_subdomains(
    domain: str,
    *,
    timeout: int,
    user_agent: str,
    rate_limit_ms: int,
    max_retries: int,
) -> Set[str]:
    """Fetch candidate subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found: Set[str] = set()
    try:
        response = get_with_retries(
            url,
            timeout=timeout,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
        )
        response.raise_for_status()
        entries = response.json()
    except Exception as exc:
        LOGGER.warning("crt.sh query failed for %s: %s", domain, exc)
        return found

    for entry in entries:
        raw_names = entry.get("name_value", "")
        for candidate in str(raw_names).splitlines():
            hostname = _normalize_host(candidate, domain)
            if hostname:
                found.add(hostname)
    return found


def _fetch_hackertarget_subdomains(
    domain: str,
    *,
    timeout: int,
    user_agent: str,
    rate_limit_ms: int,
    max_retries: int,
) -> Set[str]:
    """Fetch candidate subdomains from HackerTarget hostsearch."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    found: Set[str] = set()
    try:
        response = get_with_retries(
            url,
            timeout=timeout,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
        )
        response.raise_for_status()
        body = response.text.strip()
    except Exception as exc:
        LOGGER.warning("HackerTarget query failed for %s: %s", domain, exc)
        return found

    if not body or "error" in body.lower():
        return found

    for line in body.splitlines():
        hostname = _normalize_host(line.split(",", 1)[0], domain)
        if hostname:
            found.add(hostname)
    return found


def _bruteforce_candidates(domain: str) -> Set[str]:
    return {f"{label}.{domain}" for label in COMMON_SUBDOMAIN_LABELS}


def _resolve_existing_hosts(candidates: Iterable[str], *, dns_timeout: int) -> Set[str]:
    """Validate DNS-resolvable hostnames from a candidate set."""
    live: Set[str] = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = dns_timeout
    resolver.lifetime = dns_timeout

    for host in sorted(set(candidates)):
        for record_type in ("A", "AAAA", "CNAME"):
            try:
                resolver.resolve(host, record_type)
                live.add(host)
                break
            except Exception:
                continue
    return live


def enumerate_subdomains(
    domain: str,
    *,
    timeout: int = 15,
    dns_timeout: int = 5,
    user_agent: str = "SentinelX/2.0 Security Audit Scanner",
    sources: list[str] | None = None,
    rate_limit_ms: int = 0,
    max_retries: int = 0,
    enable_bruteforce: bool = False,
) -> list[str]:
    """Enumerate subdomains using passive public data and optional passive brute force."""
    base = domain.strip().lower()
    candidates: Set[str] = {base}
    enabled_sources = {item.lower() for item in (sources or ["crtsh", "hackertarget"])}

    if "crtsh" in enabled_sources:
        candidates.update(
            _fetch_crtsh_subdomains(
                base,
                timeout=timeout,
                user_agent=user_agent,
                rate_limit_ms=rate_limit_ms,
                max_retries=max_retries,
            )
        )
    if "hackertarget" in enabled_sources:
        candidates.update(
            _fetch_hackertarget_subdomains(
                base,
                timeout=timeout,
                user_agent=user_agent,
                rate_limit_ms=rate_limit_ms,
                max_retries=max_retries,
            )
        )
    if enable_bruteforce:
        candidates.update(_bruteforce_candidates(base))

    resolved = _resolve_existing_hosts(candidates, dns_timeout=dns_timeout)
    if not resolved:
        LOGGER.info("No resolvable subdomains found for %s; falling back to root domain.", base)
        return [base]

    return sorted(resolved)
