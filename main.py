import argparse
import asyncio

from utils.banner import show_banner
from core.logger import setup_logger
from core.engine import Engine
from core.config import Config

# ==========================
# Phase 1 — Recon
# ==========================
from recon.subdomain_enum import enumerate_subdomains
from recon.live_hosts import find_live_hosts
from recon.port_scan import scan_ports
from recon.tech_detect import detect_tech

# ==========================
# Phase 2 — Enumeration
# ==========================
from web.crawler import crawl_site
from web.js_parser import extract_js_endpoints
from web.api_mapper import map_endpoints

# ==========================
# Phase 3 — Access Control
# ==========================
from attacks.vuln_engine import run_vulnerability_checks

# ==========================
# Phase 4 — Injection
# ==========================
from attacks.injection.engine import run_injection_tests

# ==========================
# Phase 5 — Misconfiguration
# ==========================
from attacks.config.engine import run_config_tests

# ==========================
# Phase 6 — Risk Engine
# ==========================
from risk.engine import run_risk_engine

# ==========================
# Phase 7 — Reporting
# ==========================
from reporting.report_builder import build_report

from utils.helpers import save_json


def main():
    # ==========================
    # Startup
    # ==========================
    show_banner()
    logger = setup_logger()

    parser = argparse.ArgumentParser(
        description="SentinelX - Automated Attack Surface Intelligence Platform"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")

    args = parser.parse_args()

    logger.info("SentinelX initialized")

    target = args.domain.strip()

    if not target.startswith("http"):
        target = "https://" + target

    logger.info(f"Target domain: {target}")

    Engine(Config.MAX_CONCURRENCY)

    # ==================================================
    # PHASE 1 — ATTACK SURFACE DISCOVERY
    # ==================================================

    logger.info("PHASE 1 - Attack Surface Discovery")

    subdomains = enumerate_subdomains(target)

    if not subdomains:
        logger.warning("No subdomains found — using root domain")
        subdomains = [target]

    alive_hosts = asyncio.run(find_live_hosts(subdomains))

    assets = []

    for host in alive_hosts:
        hostname = host.replace("https://", "").replace("http://", "")

        assets.append({
            "host": host,
            "ports": scan_ports(hostname),
            "technologies": detect_tech(host)
        })

    save_json(assets, "assets.json")

    # ==================================================
    # PHASE 2 — WEB & API ENUMERATION
    # ==================================================

    logger.info("PHASE 2 - Web & API Enumeration")

    all_endpoints = []

    for asset in assets:
        host = asset["host"]

        crawl_eps, js_files = crawl_site(host)

        js_eps = []
        for js in js_files:
            js_eps.extend(extract_js_endpoints(js))

        mapped = map_endpoints(
            host=host,
            crawl_eps=crawl_eps,
            js_eps=js_eps
        )

        all_endpoints.extend(mapped)

    save_json(all_endpoints, "endpoints.json")

    # ==================================================
    # PHASE 3 — ACCESS CONTROL
    # ==================================================

    logger.info("PHASE 3 - Access Control Vulnerabilities")

    phase3 = run_vulnerability_checks(all_endpoints)
    save_json(phase3, "phase3_access_control.json")

    # ==================================================
    # PHASE 4 — INJECTION TESTING
    # ==================================================

    logger.info("PHASE 4 - Injection Vulnerabilities")

    phase4 = run_injection_tests(all_endpoints)
    save_json(phase4, "phase4_injection.json")

    # ==================================================
    # PHASE 5 — MISCONFIGURATION
    # ==================================================

    logger.info("PHASE 5 - Security Misconfiguration")

    phase5 = run_config_tests(all_endpoints)
    save_json(phase5, "phase5_misconfiguration.json")

    # ==================================================
    # MERGE FINDINGS
    # ==================================================

    all_findings = phase3 + phase4 + phase5
    save_json(all_findings, "all_findings_raw.json")

    # ==================================================
    # PHASE 6 — RISK SCORING
    # ==================================================

    logger.info("PHASE 6 - Risk Scoring Engine")

    scored_findings = run_risk_engine(all_findings)
    save_json(scored_findings, "risk_scored_findings.json")

    # ==================================================
    # PHASE 7 — REPORTING
    # ==================================================

    logger.info("PHASE 7 - Report Generation")

    report_path = build_report(
        target=target,
        assets=assets,
        endpoints=all_endpoints,
        findings=scored_findings
    )

    logger.info(f"Report generated successfully - {report_path}")
    logger.info("SentinelX scan completed successfully")


if __name__ == "__main__":
    main()
