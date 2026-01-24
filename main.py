import argparse
import asyncio
import time

from utils.progress import PhaseProgress

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
    # ======================================
    # GLOBAL TIMER
    # ======================================
    scan_start_time = time.time()

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

    phase2_bar = PhaseProgress(
        "PHASE 2 - Endpoint Enumeration",
        total=len(assets)
    )

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
        phase2_bar.update()

    phase2_bar.close()
    save_json(all_endpoints, "endpoints.json")

    # ==================================================
    # PHASE 3 — ACCESS CONTROL
    # ==================================================

    logger.info("PHASE 3 - Access Control Vulnerabilities")

    phase3_bar = PhaseProgress(
        "PHASE 3 - Access Control",
        total=len(all_endpoints)
    )

    phase3 = []

    for ep in all_endpoints:
        phase3.extend(run_vulnerability_checks([ep]))
        phase3_bar.update()

    phase3_bar.close()
    save_json(phase3, "phase3_access_control.json")

    # ==================================================
    # PHASE 4 — INJECTION
    # ==================================================

    logger.info("PHASE 4 - Injection Vulnerabilities")

    phase4_bar = PhaseProgress(
        "PHASE 4 - Injection Testing",
        total=len(all_endpoints)
    )

    phase4 = []

    for ep in all_endpoints:
        phase4.extend(run_injection_tests([ep]))
        phase4_bar.update()

    phase4_bar.close()
    save_json(phase4, "phase4_injection.json")

    # ==================================================
    # PHASE 5 — MISCONFIGURATION
    # ==================================================

    logger.info("PHASE 5 - Security Misconfiguration")

    phase5_bar = PhaseProgress(
        "PHASE 5 - Misconfiguration",
        total=len(all_endpoints)
    )

    phase5 = []

    for ep in all_endpoints:
        phase5.extend(run_config_tests([ep]))
        phase5_bar.update()

    phase5_bar.close()
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

    total_time = time.time() - scan_start_time

    logger.info(f"Report generated successfully - {report_path}")
    logger.info(
        f"Total scan completed in "
        f"{int(total_time // 60)}m {int(total_time % 60)}s"
    )


if __name__ == "__main__":
    main()
