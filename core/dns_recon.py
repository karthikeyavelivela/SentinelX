"""Passive DNS reconnaissance module that collects A, MX, TXT, and CNAME records."""

from __future__ import annotations

import logging
from typing import Any

import dns.resolver

LOGGER = logging.getLogger(__name__)


def _make_resolver(timeout: int) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _query(resolver: dns.resolver.Resolver, domain: str, rtype: str) -> list[str]:
    """Run a single DNS query, returning a list of record values or an empty list."""
    try:
        answers = resolver.resolve(domain, rtype)
        return [str(rdata).rstrip(".") for rdata in answers]
    except Exception as exc:
        LOGGER.debug("DNS %s query failed for %s: %s", rtype, domain, exc)
        return []


def _parse_tag_map(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for item in record.split(";"):
        part = item.strip()
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def _analyze_spf(record: str | None) -> dict[str, str]:
    if not record:
        return {
            "status": "missing",
            "severity": "High",
            "summary": "No SPF record was found. Mail spoofing protections are weak.",
            "recommendation": "Publish an SPF record and end it with -all after validation.",
        }

    lowered = record.lower()
    if "~all" in lowered:
        return {
            "status": "permissive",
            "severity": "Medium",
            "summary": "SPF is in soft-fail mode (~all), so spoofed mail may still be accepted.",
            "recommendation": "Tighten SPF to -all once legitimate senders are confirmed.",
        }
    if "?all" in lowered:
        return {
            "status": "neutral",
            "severity": "High",
            "summary": "SPF ends with ?all, which does not enforce sender validation.",
            "recommendation": "Replace ?all with -all after validating approved senders.",
        }
    if "-all" in lowered:
        return {
            "status": "enforced",
            "severity": "Low",
            "summary": "SPF appears to end with -all and is enforcing.",
            "recommendation": "Keep sender inventory current and review third-party includes regularly.",
        }
    return {
        "status": "custom",
        "severity": "Medium",
        "summary": "SPF exists but does not use a clear terminal enforcement mechanism.",
        "recommendation": "Review SPF syntax and ensure the record ends with an explicit all mechanism.",
    }


def _analyze_dmarc(record: str | None) -> dict[str, str]:
    if not record:
        return {
            "status": "missing",
            "severity": "High",
            "summary": "No DMARC record was found. Spoofed mail may bypass policy controls.",
            "recommendation": "Publish a DMARC record at _dmarc.<domain> and start with p=none if needed.",
        }

    tags = _parse_tag_map(record)
    policy = tags.get("p", "").lower()
    if policy == "none":
        return {
            "status": "monitoring_only",
            "severity": "Medium",
            "summary": "DMARC is set to p=none, which monitors abuse but does not block it.",
            "recommendation": "Move DMARC toward quarantine or reject after monitoring is stable.",
        }
    if policy in {"quarantine", "reject"}:
        return {
            "status": policy,
            "severity": "Low",
            "summary": f"DMARC policy is enforcing with p={policy}.",
            "recommendation": "Keep rua/ruf recipients monitored and review alignment regularly.",
        }
    return {
        "status": "custom",
        "severity": "Medium",
        "summary": "DMARC exists but the policy value was not recognized cleanly.",
        "recommendation": "Review DMARC syntax and ensure p=none, quarantine, or reject is set correctly.",
    }


def collect_dns_records(domain: str, *, timeout: int = 5) -> dict[str, Any]:
    """
    Collect A, MX, TXT, and CNAME records for *domain* via passive DNS resolution.

    Returns a dict with keys:
        a_records: list[str] - IPv4 addresses
        mx_records: list[str] - mail exchange hostnames with priority stripped
        txt_records: list[str] - raw TXT strings
        cname_records: list[str] - canonical name targets
        spf_record: str | None - first SPF record found
        dmarc_record: str | None - DMARC record from _dmarc.<domain>
        error: str | None - error description if all queries returned empty
    """
    LOGGER.info("Starting DNS reconnaissance for %s", domain)
    resolver = _make_resolver(timeout)

    a_records = _query(resolver, domain, "A")
    mx_raw = _query(resolver, domain, "MX")
    txt_records = _query(resolver, domain, "TXT")
    cname_records = _query(resolver, domain, "CNAME")
    dmarc_txt_records = _query(resolver, f"_dmarc.{domain}", "TXT")

    mx_records: list[str] = []
    for record in mx_raw:
        parts = record.split()
        if len(parts) == 2:
            mx_records.append(parts[1].rstrip("."))
        else:
            mx_records.append(record.rstrip("."))

    txt_clean = [record.strip('"').strip("'") for record in txt_records]
    dmarc_clean = [record.strip('"').strip("'") for record in dmarc_txt_records]

    spf = next((record for record in txt_clean if record.lower().startswith("v=spf1")), None)
    dmarc = next((record for record in dmarc_clean if record.lower().startswith("v=dmarc1")), None)
    spf_analysis = _analyze_spf(spf)
    dmarc_analysis = _analyze_dmarc(dmarc)

    all_empty = not a_records and not mx_raw and not txt_records and not cname_records and not dmarc_txt_records
    error = f"All DNS queries returned empty results for {domain}" if all_empty else None

    result = {
        "a_records": a_records,
        "mx_records": mx_records,
        "txt_records": txt_clean,
        "cname_records": cname_records,
        "spf_record": spf,
        "dmarc_record": dmarc,
        "spf_analysis": spf_analysis,
        "dmarc_analysis": dmarc_analysis,
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
