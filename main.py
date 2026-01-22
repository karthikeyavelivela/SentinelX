import argparse
import asyncio

from utils.banner import show_banner
from core.logger import setup_logger
from core.engine import Engine
from core.config import Config

from recon.subdomain_enum import enumerate_subdomains
from recon.live_hosts import find_live_hosts
from recon.port_scan import scan_ports
from recon.tech_detect import detect_tech

from utils.helpers import save_json


def main():
    # Banner
    show_banner()

    # Logger
    logger = setup_logger()

    # CLI arguments
    parser = argparse.ArgumentParser(
        description="SentinelX - Attack Surface Intelligence Platform"
    )

    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--web", action="store_true")
    parser.add_argument("--aws-scan", action="store_true")

    args = parser.parse_args()

    logger.info("SentinelX initialized")

    # Validate input
    if not args.domain:
        logger.error("No domain provided. Use -d example.com")
        return

    logger.info(f"Target domain: {args.domain}")

    # Async engine
    engine = Engine(Config.MAX_CONCURRENCY)

    # ==========================
    # PHASE 1 — RECON
    # ==========================

    logger.info("Starting Phase 1 — Attack Surface Discovery")

    # 1. Subdomain Enumeration
    subs = enumerate_subdomains(args.domain)

    if not subs:
        logger.warning("No subdomains discovered")
        return

    # 2. Live Host Detection
    alive = asyncio.run(find_live_hosts(subs))

    assets = []

    # 3. Port Scan + Tech Detection
    for host in alive:
        hostname = host.replace("https://", "").replace("http://", "")

        ports = scan_ports(hostname)
        tech = detect_tech(host)

        assets.append({
            "host": host,
            "ports": ports,
            "technologies": tech
        })

    # 4. Save results
    save_json(assets, "assets.json")

    logger.info(f"Phase 1 completed — {len(assets)} assets discovered")


if __name__ == "__main__":
    main()
