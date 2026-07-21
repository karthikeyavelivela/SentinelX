"""Favicon hashing and fingerprinting for technology stack detection."""

from __future__ import annotations

import base64
import logging
import struct
from typing import Any

from core.http_utils import get_with_retries

LOGGER = logging.getLogger(__name__)


def _mmh3_hash(data: bytes) -> int:
    """Compute MurmurHash3 (32-bit) of *data*, returning a signed int32."""
    seed = 0
    length = len(data)
    result = seed ^ length

    offset = 0
    while length >= 4:
        block = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        length -= 4

        block = (block * 0xCC9E2D51) & 0xFFFFFFFF
        block = ((block << 15) | (block >> 17)) & 0xFFFFFFFF
        block = (block * 0x1B873593) & 0xFFFFFFFF

        result ^= block
        result = ((result << 13) | (result >> 19)) & 0xFFFFFFFF
        result = (result * 5 + 0xE6546B64) & 0xFFFFFFFF

    if length > 0:
        tail = data[offset:]
        block = 0
        if length >= 3:
            block ^= tail[2] << 16
        if length >= 2:
            block ^= tail[1] << 8
        block ^= tail[0]
        block = (block * 0xCC9E2D51) & 0xFFFFFFFF
        block = ((block << 15) | (block >> 17)) & 0xFFFFFFFF
        block = (block * 0x1B873593) & 0xFFFFFFFF
        result ^= block

    result ^= len(data)
    result ^= result >> 16
    result = (result * 0x85EBCA6B) & 0xFFFFFFFF
    result ^= result >> 13
    result = (result * 0xC2B2AE35) & 0xFFFFFFFF
    result ^= result >> 16

    if result > 0x7FFFFFFF:
        result -= 0x100000000
    return result


def _shodan_favicon_hash(raw: bytes) -> int:
    """Compute a Shodan-compatible favicon hash."""
    return _mmh3_hash(base64.encodebytes(raw))


FAVICON_FINGERPRINTS: dict[int, str] = {
    -335242539: "Fortinet FortiGate",
    116323821: "Cisco WebVPN",
    -1616143106: "phpMyAdmin",
    1278547509: "Jenkins",
    # Jira/DC default favicon hash
    -1326906680: "Jira (Atlassian)",
    -244067125: "Confluence (Atlassian)",
    1820151243: "GitLab",
    -1503505223: "Grafana",
    # Atlassian status page variant; distinct hash avoids silent overwrite
    -1326906679: "Jira",
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


def fingerprint_favicon(
    domain: str,
    *,
    timeout: int = 8,
    user_agent: str = "SentinelX/2.0 Security Audit Scanner",
    rate_limit_ms: int = 0,
    max_retries: int = 0,
) -> dict[str, Any]:
    """Fetch the favicon from *domain* and compute its Shodan-compatible hash."""
    favicon_url = f"https://{domain}/favicon.ico"
    result: dict[str, Any] = {
        "hash": None,
        "technology": None,
        "favicon_url": favicon_url,
        "reachable": False,
        "error": None,
    }

    try:
        response = get_with_retries(
            favicon_url,
            timeout=timeout,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
            rate_limit_ms=rate_limit_ms,
            max_retries=max_retries,
        )
        if response.status_code == 200 and response.content:
            favicon_hash = _shodan_favicon_hash(response.content)
            result["hash"] = favicon_hash
            result["reachable"] = True
            result["technology"] = FAVICON_FINGERPRINTS.get(favicon_hash)
            LOGGER.info(
                "Favicon hash for %s: %d -> %s",
                domain,
                favicon_hash,
                result["technology"] or "unknown",
            )
        else:
            result["error"] = f"HTTP {response.status_code} from {favicon_url}"
    except Exception as exc:
        result["error"] = str(exc)
        LOGGER.debug("Favicon fetch failed for %s: %s", domain, exc)

    return result
