"""Primary scanner orchestration for SentinelX."""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

from core.dns_recon import collect_dns_records
from core.favicon_hash import fingerprint_favicon
from core.headers import inspect_security_headers
from core.port_check import probe_exposed_ports
from core.ssl_analysis import analyze_ssl
from core.subdomain import enumerate_subdomains
from core.takeover import detect_subdomain_takeovers
from core.techstack import detect_tech_stack

LOGGER = logging.getLogger(__name__)

SCANNER_VERSION = "2.1.0"
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _normalize_domain(raw_domain: str) -> str:
    value = (raw_domain or "").strip()
    if not value:
        raise ValueError("Domain is required.")

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path

    value = value.split("/")[0].split("?")[0].split("#")[0].strip().lower().rstrip(".")
    if ":" in value:
        value = value.split(":", 1)[0]

    if not _DOMAIN_PATTERN.match(value):
        raise ValueError("Invalid domain format. Provide a valid hostname such as example.com.")
    return value


def _ssl_grade(ssl_data: dict[str, Any]) -> str:
    if not ssl_data.get("reachable"):
        return "Unavailable"
    if ssl_data.get("expired"):
        return "F"
    tls_version = (ssl_data.get("tls_version") or "").upper()
    if tls_version in {"SSLV3", "TLSV1", "TLSV1.1"}:
        return "C"
    if tls_version in {"TLSV1.2", "TLSV1.3"}:
        return "A"
    return "B"


def _skip_phase(data_quality: dict[str, dict[str, str | bool]], phase_name: str, phase_timings: dict[str, float]) -> None:
    data_quality[phase_name] = {"status": "skipped", "success": False, "error": ""}
    phase_timings[phase_name] = 0.0


def run_passive_scan(
    domain: str,
    *,
    analyst_name: str = "SentinelX Automated Engine",
    analyst_email: str | None = None,
    assessment_type: str = "External Passive Reconnaissance",
    config: dict[str, Any],
    scope: str = "standard",
) -> dict[str, Any]:
    """Run all collectors and return structured scan data with resilient error handling."""
    clean_domain = _normalize_domain(domain)
    LOGGER.info("Starting SentinelX scan for %s", clean_domain)

    scan_started_at = datetime.now(timezone.utc).isoformat()
    scan_start = time.perf_counter()
    phase_timings: dict[str, float] = {}
    data_quality: dict[str, dict[str, str | bool]] = {}

    timeouts = config.get("timeouts", {})
    http_timeout = int(timeouts.get("http", 10))
    dns_timeout = int(timeouts.get("dns", 5))
    tcp_timeout = int(timeouts.get("tcp", 3))
    user_agent = str(config.get("user_agent", "SentinelX/2.0 Security Audit Scanner"))
    subdomain_sources = list(config.get("subdomain_sources", ["crtsh", "hackertarget"]))
    rate_limit_ms = int(config.get("rate_limit_ms", 0))
    max_retries = int(config.get("max_retries", 0))
    ports = [int(port) for port in config.get("ports", [])]

    enable_subdomains = scope in {"standard", "deep"}
    enable_ports = scope == "deep"
    enable_bruteforce = scope == "deep"
    enable_favicon = scope in {"standard", "deep"}
    enable_techstack = scope in {"standard", "deep"}
    enable_takeover = scope in {"standard", "deep"}

    def collect(
        phase_name: str,
        fn: Callable[..., Any],
        *args: Any,
        fallback: Any,
        **kwargs: Any,
    ) -> Any:
        started = time.perf_counter()
        try:
            result = fn(*args, **kwargs)
            data_quality[phase_name] = {"status": "ok", "success": True, "error": ""}
            return result
        except Exception as exc:
            LOGGER.exception("Collector %s failed for %s: %s", phase_name, clean_domain, exc)
            data_quality[phase_name] = {
                "status": "failed",
                "success": False,
                "error": str(exc),
            }
            return fallback
        finally:
            phase_timings[phase_name] = round(time.perf_counter() - started, 3)

    if enable_subdomains:
        subdomains = collect(
            "subdomains",
            enumerate_subdomains,
            clean_domain,
            fallback=[clean_domain],
            timeout=http_timeout,
            dns_timeout=dns_timeout,
            user_agent=user_agent,
            sources=subdomain_sources,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
            enable_bruteforce=enable_bruteforce,
        )
    else:
        subdomains = [clean_domain]
        _skip_phase(data_quality, "subdomains", phase_timings)

    ssl_data = collect(
        "ssl",
        analyze_ssl,
        clean_domain,
        fallback={"reachable": False, "error": "collector_failed"},
        timeout=tcp_timeout,
    )

    headers_data = collect(
        "headers",
        inspect_security_headers,
        clean_domain,
        fallback={"target_url": f"https://{clean_domain}", "headers": [], "present": {}, "missing": [], "error": "collector_failed"},
        timeout=http_timeout,
        user_agent=user_agent,
        rate_limit_ms=rate_limit_ms,
        max_retries=max_retries,
    )

    if enable_ports:
        ports_data = collect(
            "ports",
            probe_exposed_ports,
            clean_domain,
            fallback=[],
            ports=ports,
            timeout=tcp_timeout,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
        )
    else:
        ports_data = []
        _skip_phase(data_quality, "ports", phase_timings)

    if enable_favicon:
        favicon_data = collect(
            "favicon",
            fingerprint_favicon,
            clean_domain,
            fallback={
                "hash": None,
                "technology": None,
                "favicon_url": f"https://{clean_domain}/favicon.ico",
                "reachable": False,
                "error": "collector_failed",
            },
            timeout=http_timeout,
            user_agent=user_agent,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
        )
    else:
        favicon_data = {
            "hash": None,
            "technology": None,
            "favicon_url": f"https://{clean_domain}/favicon.ico",
            "reachable": False,
            "error": "skipped_by_scope",
        }
        _skip_phase(data_quality, "favicon", phase_timings)

    if enable_techstack:
        techstack_data = collect(
            "techstack",
            detect_tech_stack,
            clean_domain,
            fallback=[],
            timeout=http_timeout,
            user_agent=user_agent,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
            favicon_fingerprint=favicon_data,
        )
    else:
        techstack_data = []
        _skip_phase(data_quality, "techstack", phase_timings)

    dns_data = collect(
        "dns",
        collect_dns_records,
        clean_domain,
        fallback={
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "cname_records": [],
            "spf_record": None,
            "dmarc_record": None,
            "spf_analysis": {"status": "unknown", "severity": "Low", "summary": "DNS collector failed."},
            "dmarc_analysis": {"status": "unknown", "severity": "Low", "summary": "DNS collector failed."},
            "error": "collector_failed",
        },
        timeout=dns_timeout,
    )

    if enable_takeover:
        takeover_data = collect(
            "takeover",
            detect_subdomain_takeovers,
            subdomains,
            fallback=[],
            dns_timeout=dns_timeout,
            http_timeout=http_timeout,
            user_agent=user_agent,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
        )
    else:
        takeover_data = []
        _skip_phase(data_quality, "takeover", phase_timings)

    total_time = round(time.perf_counter() - scan_start, 3)
    missing_headers = len(headers_data.get("missing", [])) if isinstance(headers_data, dict) else 0

    LOGGER.info(
        "Scan summary domain=%s scope=%s subdomains=%d open_ports=%d missing_headers=%d ssl_grade=%s total_time=%.3fs",
        clean_domain,
        scope,
        len(subdomains),
        len(ports_data),
        missing_headers,
        _ssl_grade(ssl_data),
        total_time,
    )

    return {
        "domain": clean_domain,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_start_time": scan_started_at,
        "analyst_name": analyst_name,
        "analyst_email": analyst_email,
        "assessment_type": assessment_type,
        "scope": scope,
        "subdomains": subdomains,
        "ssl": ssl_data,
        "headers": headers_data,
        "ports": ports_data,
        "favicon": favicon_data,
        "techstack": techstack_data,
        "dns": dns_data,
        "takeover_findings": takeover_data,
        "phase_timings": phase_timings,
        "scan_duration_seconds": total_time,
        "data_quality": data_quality,
        "scanner_version": SCANNER_VERSION,
        "config_snapshot": {
            "timeouts": timeouts,
            "ports": ports,
            "user_agent": user_agent,
            "subdomain_sources": subdomain_sources,
            "rate_limit_ms": rate_limit_ms,
            "max_retries": max_retries,
            "scope": scope,
        },
    }
