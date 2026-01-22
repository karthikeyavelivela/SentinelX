import argparse
import asyncio

from utils.banner import show_banner
from core.logger import setup_logger
from core.engine import Engine
from core.config import Config

def main():
    show_banner()
    logger = setup_logger()

    parser = argparse.ArgumentParser(
        description="SentinelX - Attack Surface Intelligence Platform"
    )

    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("--deep", action="store_true", help="Deep scan")
    parser.add_argument("--web", action="store_true", help="Web only scan")
    parser.add_argument("--aws-scan", action="store_true", help="AWS scan only")

    args = parser.parse_args()

    logger.info("SentinelX initialized")

    if args.domain:
        logger.info(f"Target domain: {args.domain}")

    engine = Engine(Config.MAX_CONCURRENCY)

    logger.info("Phase 0 completed successfully")

if __name__ == "__main__":
    main()
