"""Passive DNS reconnaissance module — collects A, MX, TXT, and CNAME records."""

from __future__ import annotations

import logging
from typing import Any

import dns.resolver

LOGGER = logging.getLogger(__name__)

_RESOLVER_TIMEOUT = 5


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = _RESOLVER_TIMEOUT
    r.lifetime = _RESOLVER_TIMEOUT
    return r


def _query(resolver: dns.resolver.Resolver, domain: str, rtype: str) -> list[str]:
    """Run a single DNS query, returning a list of record values (or empty on failure)."""
    try:
        answers = resolver.resolve(domain, rtype)
        return [str(rdata).rstrip(".") for rdata in answers]
    except Exception as exc:
        LOGGER.debug("DNS %s query failed for %s: %s", rtype, domain, exc)
        return []


def collect_dns_records(domain: str) -> dict[str, Any]:
    """
    Collect A, MX, TXT, and CNAME records for *domain* via passive DNS resolution.

    Returns a dict with keys:
        a_records  : list[str]  — IPv4 addresses
        mx_records : list[str]  — mail exchange hostnames (with priority stripped)
        txt_records: list[str]  — raw TXT strings (SPF, DMARC, DKIM, etc.)
        cname_records: list[str] — canonical name targets
        spf_record : str | None — first SPF record found (convenience)
        dmarc_record: str | None — first DMARC record found (convenience)
        error      : str | None — error description if all queries failed
    """
    LOGGER.info("Starting DNS reconnaissance for %s", domain)
    resolver = _make_resolver()

    a_records = _query(resolver, domain, "A")
    mx_raw = _query(resolver, domain, "MX")
    txt_records = _query(resolver, domain, "TXT")
    cname_records = _query(resolver, domain, "CNAME")

    # MX records contain priority + hostname; strip priority prefix
    mx_records: list[str] = []
    for record in mx_raw:
        parts = record.split()
        if len(parts) == 2:
            mx_records.append(parts[1].rstrip("."))
        else:
            mx_records.append(record.rstrip("."))

    # Clean up TXT — remove surrounding quotes
    txt_clean = [r.strip('"').strip("'") for r in txt_records]

    spf = next((r for r in txt_clean if r.lower().startswith("v=spf")), None)
    dmarc = next((r for r in txt_clean if "v=dmarc" in r.lower()), None)

    all_empty = not a_records and not mx_raw and not txt_records and not cname_records
    error = f"All DNS queries returned empty results for {domain}" if all_empty else None

    result = {
        "a_records": a_records,
        "mx_records": mx_records,
        "txt_records": txt_clean,
        "cname_records": cname_records,
        "spf_record": spf,
        "dmarc_record": dmarc,
        "error": error,
    }
    LOGGER.info(
        "DNS recon complete for %s: %d A, %d MX, %d TXT, %d CNAME",
        domain,
        len(a_records),
        len(mx_records),
        len(txt_clean),
        len(cname_records),
    )
    return result
