"""SentinelX passive external SaaS exposure intelligence pipeline."""

from __future__ import annotations

import argparse
import logging

from core.scanner import run_passive_scan
from reporting.ai_generator import generate_ai_report
from reporting.formatter import build_structured_output, save_json
from reporting.html_renderer import render_html_report


def configure_logging() -> None:
    """Configure application logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="SentinelX - External SaaS Exposure Intelligence Engine (Passive)",
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    return parser.parse_args()


def main() -> None:
    """Run passive scan pipeline and generate all report artifacts."""
    configure_logging()
    args = parse_args()
    logger = logging.getLogger("sentinelx.main")

    try:
        logger.info("Scan pipeline initiated for domain: %s", args.domain)
        scan_data = run_passive_scan(args.domain)
        structured_output = build_structured_output(scan_data)
        save_json(structured_output, "structured_output.json")
        logger.info("Structured output saved to structured_output.json")

        ai_report = generate_ai_report(
            structured_input_path="structured_output.json",
            output_path="ai_report.json",
        )
        logger.info("AI report saved to ai_report.json")

        render_html_report(
            structured_data=structured_output,
            ai_data=ai_report,
            output_path="final_report.html",
        )
        logger.info("HTML report saved to final_report.html")

        logger.info("Scan pipeline completed successfully for %s", args.domain)
        print("SentinelX Premium Exposure Report generated successfully.")
    except ValueError as exc:
        logger.error("Invalid input — %s", exc)
        raise SystemExit(1) from exc
    except Exception as exc:
        logger.exception("Pipeline failed: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()

