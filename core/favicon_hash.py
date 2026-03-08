"""Favicon hashing and fingerprinting for technology stack detection.

Uses the MurmurHash3 algorithm (same as Shodan) to hash the favicon bytes,
then cross-references against a known fingerprint database.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import struct
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MurmurHash3 (32-bit) — Python implementation matching Shodan's convention
# ---------------------------------------------------------------------------

def _mmh3_hash(data: bytes) -> int:
    """Compute MurmurHash3 (32-bit) of *data*, returning a signed int32."""
    seed = 0
    length = len(data)
    h = seed ^ length

    off = 0
    while length >= 4:
        k = struct.unpack_from("<I", data, off)[0]
        off += 4
        length -= 4

        k = (k * 0xCC9E2D51) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * 0x1B873593) & 0xFFFFFFFF

        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    if length > 0:
        tail = data[off:]
        k = 0
        if length >= 3:
            k ^= tail[2] << 16
        if length >= 2:
            k ^= tail[1] << 8
        k ^= tail[0]
        k = (k * 0xCC9E2D51) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * 0x1B873593) & 0xFFFFFFFF
        h ^= k

    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16

    # Convert to signed int32 (Shodan convention)
    if h > 0x7FFFFFFF:
        h -= 0x100000000
    return h


def _shodan_favicon_hash(raw: bytes) -> int:
    """Compute Shodan-compatible favicon hash: base64-encode → MurmurHash3."""
    b64 = base64.encodebytes(raw)
    return _mmh3_hash(b64)


# ---------------------------------------------------------------------------
# Known Favicon Fingerprints (hash → technology name)
# ---------------------------------------------------------------------------

FAVICON_FINGERPRINTS: dict[int, str] = {
    # Discovered via Shodan research / public databases
    -335242539: "Fortinet FortiGate",
    116323821: "Cisco WebVPN",
    -1616143106: "phpMyAdmin",
    1278547509: "Jenkins",
    -1326906680: "Jira (Atlassian)",
    -244067125: "Confluence (Atlassian)",
    1820151243: "GitLab",
    -1503505223: "Grafana",
    -1326906680: "Jira",
    -1148354440: "Kibana",
    708578229: "Elasticsearch",
    -1821527313: "SonarQube",
    -1859902848: "RabbitMQ Management",
    1649987671: "Jupyter Notebook",
    -1483816757: "Prometheus",
    -566750536: "Traefik",
    1474940609: "Portainer",
    -1259903520: "Rancher",
    393325149: "Apache Tomcat",
    -1456854750: "Nginx Default Page",
    32788288: "IIS Windows Server",
    -1388401860: "WordPress",
    771104874: "Drupal",
    -1182814289: "Shopify",
    -1777027143: "Magento",
    -1741217875: "Ghost CMS",
    1873853139: "Wix",
    -694862979: "Squarespace",
    -1560258481: "Webflow",
    539278534: "Keycloak",
    -674114434: "HashiCorp Vault",
    -1524604072: "Kubernetes Dashboard",
    1471454465: "Nextcloud",
    -1007696748: "Mattermost",
    -442057516: "Rocket.Chat",
    1469480177: "Zabbix",
    -1604726652: "Nagios",
    1655453652: "Datadog",
    162911087: "Sentry",
    -476181163: "PGAdmin",
    1180940500: "MinIO",
    -1723839820: "Swagger UI",
    1352578751: "Redoc",
    -574888449: "Palo Alto GlobalProtect",
    -1547390048: "OpenVPN Access Server",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fingerprint_favicon(domain: str, timeout: int = 8) -> dict[str, Any]:
    """
    Fetch favicon from *domain* and compute its Shodan-compatible hash.

    Returns:
        hash (int | None)          : MurmurHash3 of base64-encoded favicon bytes
        technology (str | None)    : matched technology from fingerprint DB
        favicon_url (str)          : URL used to fetch favicon
        reachable (bool)           : whether the favicon was successfully fetched
        error (str | None)         : error message if unreachable
    """
    favicon_url = f"https://{domain}/favicon.ico"
    result: dict[str, Any] = {
        "hash": None,
        "technology": None,
        "favicon_url": favicon_url,
        "reachable": False,
        "error": None,
    }

    try:
        response = requests.get(
            favicon_url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SentinelX/1.2)"},
        )
        if response.status_code == 200 and response.content:
            favicon_hash = _shodan_favicon_hash(response.content)
            result["hash"] = favicon_hash
            result["reachable"] = True
            matched = FAVICON_FINGERPRINTS.get(favicon_hash)
            result["technology"] = matched
            LOGGER.info(
                "Favicon hash for %s: %d  →  %s",
                domain,
                favicon_hash,
                matched or "unknown",
            )
        else:
            result["error"] = f"HTTP {response.status_code} from {favicon_url}"
            LOGGER.debug("Favicon not found at %s (HTTP %d)", favicon_url, response.status_code)
    except Exception as exc:
        result["error"] = str(exc)
        LOGGER.debug("Favicon fetch failed for %s: %s", domain, exc)

    return result
