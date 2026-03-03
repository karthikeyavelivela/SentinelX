"""Passive subdomain enumeration utilities."""

from __future__ import annotations

import logging
from typing import Set

import dns.resolver
import requests

LOGGER = logging.getLogger(__name__)


def _fetch_crtsh_subdomains(domain: str, timeout: int = 15) -> Set[str]:
    """Fetch candidate subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found: Set[str] = set()
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        entries = response.json()
    except Exception as exc:
        LOGGER.warning("crt.sh query failed for %s: %s", domain, exc)
        return found

    for entry in entries:
        raw_names = entry.get("name_value", "")
        for candidate in str(raw_names).splitlines():
            hostname = candidate.strip().lower().lstrip("*.")  # wildcard cleanup
            if hostname.endswith(domain):
                found.add(hostname)
    return found


def _resolve_existing_hosts(candidates: Set[str]) -> Set[str]:
    """Validate DNS-resolvable hostnames from a candidate set."""
    live: Set[str] = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    for host in candidates:
        try:
            resolver.resolve(host, "A")
            live.add(host)
        except Exception:
            continue
    return live


def enumerate_subdomains(domain: str) -> list[str]:
    """Enumerate subdomains using passive public certificate transparency data."""
    base = domain.strip().lower()
    candidates = _fetch_crtsh_subdomains(base)
    candidates.add(base)

    resolved = _resolve_existing_hosts(candidates)
    if not resolved:
        LOGGER.info("No resolvable subdomains found for %s; falling back to root domain.", base)
        return [base]

    return sorted(resolved)

