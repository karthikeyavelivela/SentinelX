"""SentinelX CLI entrypoint."""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

from core.consent import AuthorizationDeclined, ensure_authorization
from core.drift_tracker import (
    build_baseline_comparison,
    load_baseline_snapshot,
    save_baseline_snapshot,
)
from core.runtime_config import load_runtime_config
from core.scanner import run_passive_scan
from reporting.ai_generator import generate_ai_report
from reporting.formatter import build_structured_output, save_json
from reporting.html_renderer import render_html_report
from reporting.pdf_exporter import export_pdf


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SentinelX - external exposure intelligence engine")
    parser.add_argument("domain", nargs="?", help="Target domain (positional), e.g. example.com")
    parser.add_argument("-d", "--domain", dest="domain_flag", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--analyst",
        default="SentinelX Automated Engine",
        help="Analyst name for report metadata",
    )
    parser.add_argument(
        "--analyst-email",
        dest="analyst_email",
        default=None,
        help="Contact email shown in the report closing line for remediation follow-up.",
    )
    parser.add_argument(
        "--assessment-type",
        default="External Passive Reconnaissance",
        help="Assessment type label",
    )
    parser.add_argument(
        "--scope",
        choices=("quick", "standard", "deep"),
        default="standard",
        help="Scan depth: quick (DNS/headers/SSL), standard (all passive modules, no ports), deep (all modules + ports + brute force).",
    )
    parser.add_argument(
        "--format",
        choices=("pdf", "html", "json", "all"),
        default="pdf",
        help="Output format. Default: pdf.",
    )
    parser.add_argument(
        "--compare",
        choices=("last",),
        help="Compare the current scan against the last stored baseline snapshot.",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Opt in to external OpenAI-assisted narrative generation when OPENAI_API_KEY is set.",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to YAML runtime configuration file.",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for output artifacts (default: current directory).",
    )
    parser.add_argument(
        "--delay-ms",
        type=int,
        help="Override the configured delay between outbound requests in milliseconds.",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Deprecated compatibility flag. Saves a fresh baseline snapshot and skips comparison.",
    )
    parser.add_argument(
        "--i-have-authorization",
        dest="i_have_authorization",
        action="store_true",
        help="Skip the interactive authorization prompt (non-interactive/CI use, or invoked by the GUI).",
    )
    parser.add_argument(
        "--no-pdf",
        action="store_true",
        help="Deprecated compatibility flag. Use --format html or --format json instead.",
    )
    args = parser.parse_args()

    provided = [value for value in (args.domain, args.domain_flag) if value]
    if not provided:
        parser.error("domain is required. Use positional DOMAIN or -d DOMAIN.")
    if args.domain and args.domain_flag and args.domain != args.domain_flag:
        parser.error("positional domain and -d/--domain must match when both are provided.")
    if args.delay_ms is not None and args.delay_ms < 0:
        parser.error("--delay-ms must be zero or greater.")
    args.domain = args.domain_flag or args.domain

    if args.no_pdf and args.format == "pdf":
        args.format = "html"
    if args.baseline and args.compare:
        parser.error("--baseline and --compare last cannot be used together.")
    return args


def _should_render_html(output_format: str) -> bool:
    return output_format in {"html", "pdf", "all"}


def _should_render_pdf(output_format: str) -> bool:
    return output_format in {"pdf", "all"}


def _should_render_final_json(output_format: str) -> bool:
    return output_format in {"json", "all"}


def main() -> None:
    configure_logging()
    args = parse_args()
    logger = logging.getLogger("sentinelx.main")
    started = time.perf_counter()
    config, config_path = load_runtime_config(args.config)

    if args.delay_ms is not None:
        config["rate_limit_ms"] = args.delay_ms

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_data_path = output_dir / "scan_data.json"
    structured_path = output_dir / "structured_output.json"
    ai_path = output_dir / "ai_report.json"
    json_report_path = output_dir / "final_report.json"
    html_path = output_dir / "final_report.html"
    pdf_path = output_dir / "final_report.pdf"
    baseline_root = Path(".sentinelx").resolve()

    try:
        ensure_authorization(
            domain=args.domain,
            consent_root=str(baseline_root),
            email=args.analyst_email,
            non_interactive=args.i_have_authorization,
        )

        logger.info("Scan pipeline initiated for domain: %s", args.domain)
        logger.info("Analyst: %s | Assessment type: %s", args.analyst, args.assessment_type)
        logger.info("Loaded runtime config from %s", config_path)

        scan_data = run_passive_scan(
            domain=args.domain,
            analyst_name=args.analyst,
            analyst_email=args.analyst_email,
            assessment_type=args.assessment_type,
            config=config,
            scope=args.scope,
        )
        save_json(scan_data, str(scan_data_path))

        structured_output = build_structured_output(scan_data)

        baseline_snapshot = None
        if args.compare == "last":
            baseline_snapshot = load_baseline_snapshot(str(baseline_root), scan_data["domain"])
            structured_output["comparison_report"] = build_baseline_comparison(
                current_scan_data=scan_data,
                current_structured_output=structured_output,
                baseline_snapshot=baseline_snapshot,
            )
            save_baseline_snapshot(
                baseline_root=str(baseline_root),
                domain=scan_data["domain"],
                scan_data=scan_data,
                structured_output=structured_output,
            )
        elif args.baseline:
            structured_output["comparison_report"] = build_baseline_comparison(
                current_scan_data=scan_data,
                current_structured_output=structured_output,
                baseline_snapshot=None,
            )
            save_baseline_snapshot(
                baseline_root=str(baseline_root),
                domain=scan_data["domain"],
                scan_data=scan_data,
                structured_output=structured_output,
            )
        else:
            structured_output["comparison_report"] = {"status": "disabled", "reason": "compare_flag_not_requested"}

        ai_report = None
        if args.ai:
            ai_report = generate_ai_report(
                structured_data=structured_output,
                output_path=str(ai_path),
                ai_mode="openai",
            )

        save_json(structured_output, str(structured_path))

        if _should_render_final_json(args.format):
            save_json(structured_output, str(json_report_path))

        if _should_render_html(args.format):
            render_html_report(
                structured_data=structured_output,
                ai_data=ai_report,
                output_path=str(html_path),
            )

        if _should_render_pdf(args.format):
            if not _should_render_html(args.format):
                render_html_report(
                    structured_data=structured_output,
                    ai_data=ai_report,
                    output_path=str(html_path),
                )
            pdf_result = export_pdf(str(html_path), str(pdf_path))
        else:
            pdf_result = {"path": None, "status": "skipped", "engine": "format_disabled"}

        structured_output["assessment_metadata"]["pdf_status"] = pdf_result["status"]
        structured_output["assessment_metadata"]["pdf_engine"] = pdf_result["engine"]
        save_json(structured_output, str(structured_path))
        if _should_render_final_json(args.format):
            save_json(structured_output, str(json_report_path))

        artifact_lines = [f"    [OK]   {scan_data_path}", f"    [OK]   {structured_path}"]
        if args.ai and ai_report is not None:
            artifact_lines.append(f"    [OK]   {ai_path}")
        if _should_render_final_json(args.format):
            artifact_lines.append(f"    [OK]   {json_report_path}")
        if _should_render_html(args.format):
            artifact_lines.append(f"    [OK]   {html_path}")
        if _should_render_pdf(args.format):
            if pdf_result["status"] == "placeholder_pdf":
                artifact_lines.append(f"    [WARN] {pdf_path} (placeholder PDF via {pdf_result['engine']})")
            elif pdf_result["status"] == "full_pdf":
                artifact_lines.append(f"    [OK]   {pdf_path} ({pdf_result['engine']})")
            else:
                artifact_lines.append(f"    [SKIP] {pdf_path} ({pdf_result['engine']})")

        total_duration = time.perf_counter() - started
        print("\n" + "=" * 60)
        print("  SentinelX v2.0 - Scan Complete")
        print("=" * 60)
        print(f"  Target   : {scan_data.get('domain', args.domain)}")
        print(f"  Scope    : {args.scope}")
        print(f"  Format   : {args.format}")
        print(f"  Analyst  : {args.analyst}")
        print(f"  Duration : {total_duration:.2f}s")
        print()
        print("  Output Files:")
        for line in artifact_lines:
            print(line)
        print("=" * 60 + "\n")

    except AuthorizationDeclined as exc:
        logger.error("Authorization declined - %s", exc)
        raise SystemExit(1) from exc
    except ValueError as exc:
        logger.error("Invalid input - %s", exc)
        raise SystemExit(1) from exc
    except Exception as exc:
        logger.exception("Pipeline failed: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
