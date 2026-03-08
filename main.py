"""SentinelX passive external SaaS exposure intelligence pipeline — consulting-grade edition."""

from __future__ import annotations

import argparse
import logging

from core.scanner import run_passive_scan
from reporting.ai_generator import generate_ai_report
from reporting.formatter import build_structured_output, save_json
from reporting.html_renderer import render_html_report
from reporting.pdf_exporter import export_pdf


def configure_logging() -> None:
    """Configure application logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="SentinelX v1.2 — External SaaS Exposure Intelligence Engine (Passive)",
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--analyst",
        default="SentinelX Automated Engine",
        help="Analyst name for the Assessment Metadata section (default: SentinelX Automated Engine)",
    )
    parser.add_argument(
        "--assessment-type",
        default="External Passive Reconnaissance",
        help="Assessment type label (default: External Passive Reconnaissance)",
    )
    return parser.parse_args()


def main() -> None:
    """Run passive scan pipeline and generate all report artifacts."""
    configure_logging()
    args = parse_args()
    logger = logging.getLogger("sentinelx.main")

    try:
        logger.info("Scan pipeline initiated for domain: %s", args.domain)
        logger.info("Analyst: %s | Assessment type: %s", args.analyst, args.assessment_type)

        # --- Stage 1: Passive Intelligence Collection ---
        scan_data = run_passive_scan(
            domain=args.domain,
            analyst_name=args.analyst,
            assessment_type=args.assessment_type,
        )

        # --- Stage 2: Structured Output ---
        structured_output = build_structured_output(scan_data)
        save_json(structured_output, "structured_output.json")
        logger.info("Structured output saved → structured_output.json")

        # --- Stage 3: AI-Enhanced Report ---
        ai_report = generate_ai_report(
            structured_input_path="structured_output.json",
            output_path="ai_report.json",
        )
        logger.info("AI report saved → ai_report.json")

        # --- Stage 4: HTML Report ---
        render_html_report(
            structured_data=structured_output,
            ai_data=ai_report,
            output_path="final_report.html",
        )
        logger.info("HTML report saved → final_report.html")

        # --- Stage 5: PDF Export ---
        pdf_path = export_pdf("final_report.html", "final_report.pdf")
        if pdf_path:
            logger.info("PDF report saved → final_report.pdf")
        else:
            logger.warning("PDF export skipped (WeasyPrint not available).")

        # --- Summary ---
        print("\n" + "=" * 60)
        print("  SentinelX v1.2 — Scan Complete")
        print("=" * 60)
        print(f"  Target   : {args.domain}")
        print(f"  Analyst  : {args.analyst}")
        print()
        print("  Output Files:")
        print("    ✔  structured_output.json")
        print("    ✔  ai_report.json")
        print("    ✔  final_report.html")
        print(f"    {'✔' if pdf_path else '⚠'}  final_report.pdf{'  (generated)' if pdf_path else '  (skipped — install weasyprint)'}")
        print("=" * 60 + "\n")

    except ValueError as exc:
        logger.error("Invalid input — %s", exc)
        raise SystemExit(1) from exc
    except Exception as exc:
        logger.exception("Pipeline failed: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
