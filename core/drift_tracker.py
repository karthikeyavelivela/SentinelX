"""Historical scan drift tracking for SentinelX."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _baseline_path(baseline_root: str, domain: str) -> Path:
    return Path(baseline_root) / f"{domain}_baseline.json"


def load_baseline_snapshot(baseline_root: str, domain: str) -> dict[str, Any] | None:
    path = _baseline_path(baseline_root, domain)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_baseline_snapshot(
    *,
    baseline_root: str,
    domain: str,
    scan_data: dict[str, Any],
    structured_output: dict[str, Any],
) -> str:
    path = _baseline_path(baseline_root, domain)
    path.parent.mkdir(parents=True, exist_ok=True)
    snapshot = {
        "scan_data": scan_data,
        "structured_output": structured_output,
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2)
    return str(path)


def _header_map(snapshot: dict[str, Any]) -> dict[str, str]:
    headers = snapshot.get("scan_data", {}).get("headers", {}).get("headers", [])
    mapping: dict[str, str] = {}
    for item in headers:
        if not isinstance(item, dict):
            continue
        mapping[str(item.get("name", ""))] = str(item.get("status", ""))
    return mapping


def build_baseline_comparison(
    *,
    current_scan_data: dict[str, Any],
    current_structured_output: dict[str, Any],
    baseline_snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    if baseline_snapshot is None:
        return {
            "status": "baseline_created",
            "reason": "no_existing_baseline",
            "new_subdomains": [],
            "new_open_ports": [],
            "changed_headers": [],
            "new_findings": [],
        }

    previous_scan = baseline_snapshot.get("scan_data", {})
    previous_structured = baseline_snapshot.get("structured_output", {})

    current_subdomains = set(current_scan_data.get("subdomains", []))
    previous_subdomains = set(previous_scan.get("subdomains", []))
    current_ports = set(current_scan_data.get("ports", []))
    previous_ports = set(previous_scan.get("ports", []))

    current_findings = {str(item.get("title", "")) for item in current_structured_output.get("findings", [])}
    previous_findings = {str(item.get("title", "")) for item in previous_structured.get("findings", [])}
    current_findings.discard("")
    previous_findings.discard("")

    current_headers = _header_map({"scan_data": current_scan_data})
    previous_headers = _header_map(baseline_snapshot)
    changed_headers: list[dict[str, str]] = []
    for header_name in sorted(set(current_headers) | set(previous_headers)):
        before = previous_headers.get(header_name, "absent")
        after = current_headers.get(header_name, "absent")
        if before != after:
            changed_headers.append({"header": header_name, "before": before, "after": after})

    return {
        "status": "compared",
        "reason": "baseline_loaded",
        "new_subdomains": sorted(current_subdomains - previous_subdomains),
        "removed_subdomains": sorted(previous_subdomains - current_subdomains),
        "new_open_ports": sorted(current_ports - previous_ports),
        "closed_ports": sorted(previous_ports - current_ports),
        "changed_headers": changed_headers,
        "new_findings": sorted(current_findings - previous_findings),
        "resolved_findings": sorted(previous_findings - current_findings),
    }
