# SentinelX Audit

## Scope

This audit covers the repo-owned source, config, template, documentation, and representative generated artifacts in `C:\Users\veliv\Desktop\sentinelx`.

Excluded from function-level analysis:

- `.git/`
- `.venv/`, `venv/`
- `__pycache__/`
- binary PDF artifacts

Those directories were inventoried before edits, but they are not part of the application logic.

## Step 1: File Audit

### Application Source

| File | What it does | Functions / Classes | External APIs / Services | Notes / Bugs |
|------|--------------|---------------------|--------------------------|--------------|
| `main.py` | CLI entrypoint that parses flags, runs scans, builds reports, and saves outputs. | `configure_logging()`: sets log format. `parse_args()`: defines CLI flags and normalizes deprecated behavior. `_should_render_html()`, `_should_render_pdf()`, `_should_render_final_json()`: output gating helpers. `main()`: full pipeline orchestration. | Local file system, optional OpenAI path via reporting module. | Fixed missing `--scope`, `--format`, `--compare`, and `--delay-ms` support. Fixed AI export so it is opt-in. |
| `core/scanner.py` | Orchestrates all collection phases with scope-aware skipping and fault isolation. | `_normalize_domain()`: validates and strips URLs to hostnames. `_ssl_grade()`: coarse TLS grade. `_skip_phase()`: marks scope-skipped modules. `run_passive_scan()`: runs collectors based on quick/standard/deep scope. | DNS resolution, HTTP requests, socket/TLS connections through child modules. | Fixed scope handling and deep-mode brute force trigger. |
| `core/dns_recon.py` | Collects DNS records and evaluates SPF/DMARC posture. | `_make_resolver()`: builds resolver. `_query()`: safe DNS lookup. `_parse_tag_map()`: parses semicolon tags. `_analyze_spf()`: classifies SPF strength. `_analyze_dmarc()`: classifies DMARC policy. `collect_dns_records()`: main DNS collector. | Public DNS. | Verified DMARC query uses `_dmarc.{domain}`. Added policy parsing and severity mapping. |
| `core/subdomain.py` | Enumerates passive and optional brute-force subdomains, then resolves live hosts. | `_normalize_host()`: cleans candidate hostnames. `_fetch_crtsh_subdomains()`: queries `crt.sh`. `_fetch_hackertarget_subdomains()`: queries HackerTarget hostsearch. `_bruteforce_candidates()`: builds passive brute-force list. `_resolve_existing_hosts()`: confirms DNS resolution. `enumerate_subdomains()`: main enumerator. | `https://crt.sh/`, `https://api.hackertarget.com/hostsearch/`, DNS. | Verified `crt.sh` URL is not double-encoding domain. Added fallback source and brute-force candidates. |
| `core/headers.py` | Scores security headers individually and outputs structured header rows. | `_evaluate_header()`: PASS/WARN/FAIL grading per header. `inspect_security_headers()`: fetches HTTPS response and scores all tracked headers, or marks them UNKNOWN on transport failure. | Target HTTPS endpoint. | Fixed transport failure handling so headers become `UNKNOWN`, not falsely missing. Added more headers and structured table output. |
| `core/http_utils.py` | Shared GET helper with retries and request spacing. | `rate_limit_sleep()`: sleeps between requests. `get_with_retries()`: retrying GET wrapper. | `requests`. | Existing rate limiting kept; now exposed via CLI override. |
| `core/port_check.py` | Lightweight public TCP port probing. | `probe_exposed_ports()`: checks configured ports with retries and delay. | Target TCP services. | Existing logic retained; deep scope now controls when it runs. |
| `core/ssl_analysis.py` | Collects public TLS certificate metadata from port 443. | `analyze_ssl()`: opens socket, wraps TLS, extracts certificate fields. | Target TLS service. | No critical logic bug found in current version. |
| `core/favicon_hash.py` | Fetches favicons, computes Shodan-style hash, maps known products. | `_mmh3_hash()`: MurmurHash3 implementation. `_shodan_favicon_hash()`: base64-compatible wrapper. `fingerprint_favicon()`: fetch and fingerprint favicon. | Target `/favicon.ico`. | Current source already avoids the duplicate `-1326906680` overwrite by using a distinct second key. |
| `core/techstack.py` | Uses HTML, headers, and favicon hints to infer likely technologies. | `_generator_content()`: pulls meta generator tag. `_signature_matches()`: tests patterns. `detect_tech_stack()`: fetches page and scores signatures. | Target HTTPS endpoint. | No new critical bug found; existing behavior is best-effort and safely wrapped. |
| `core/takeover.py` | Detects possible dangling CNAME takeover exposure. | `_make_resolver()`: resolver builder. `_resolve_cname_chain()`: follows CNAME chain. `_service_for_chain()`: maps known provider suffixes. `detect_subdomain_takeovers()`: builds takeover findings. | DNS, target HTTP/HTTPS endpoints. | No critical logic bug found in current version. |
| `core/drift_tracker.py` | Stores rolling baselines and historical snapshots, and computes diffs. | `_history_dir()`, `_baseline_path()`: path helpers. `load_previous_snapshot()`: reads legacy scan history. `save_scan_snapshot()`: writes history. `load_baseline_snapshot()`: reads rolling baseline. `save_baseline_snapshot()`: writes rolling baseline. `_header_map()`: maps header names to statuses. `build_baseline_comparison()`: computes new subdomains, ports, header changes, findings. | Local file system only. | Added `--compare last` support requested by user. |
| `core/runtime_config.py` | Loads YAML config with defaults and deep merge. | `_deep_merge()`: recursive merge. `load_runtime_config()`: reads config or defaults. | Local YAML config. | Updated default sources to include HackerTarget. |
| `core/__init__.py` | Package marker for core modules. | None. | None. | No issues. |
| `reporting/formatter.py` | Converts collector output into findings, scoring, executive summary, and module sections. | `_module_ok()`, `_severity_to_cvss()`, `_finding_module()`, `_make_finding()`, `_build_findings()`, `_risk_buckets()`, `_compute_exposure_score()`, `_build_completeness_note()`, `_severity_counts()`, `_build_module_sections()`, `_build_executive_summary()`, `build_structured_output()`, `save_json()`. | Local JSON output only. | Added 100-point score, executive summary, findings table, module sections, DNS/email findings, and baseline comparison integration. |
| `reporting/html_renderer.py` | Renders report HTML from structured data and optional AI narrative. | `_build_port_appendix()`, `_build_ssl_appendix()`, `render_html_report()`. | Jinja2 templates. | Simplified renderer to use structured data directly so reports work with or without AI. |
| `reporting/ai_generator.py` | Optional OpenAI summary generator with fallback summary. | `_fallback_ai_report()`, `_extract_response_text()`, `_is_internal_ip()`, `_redact_value()`, `_redact_structured_payload()`, `generate_ai_report()`. | OpenAI API, only when `--ai` and `OPENAI_API_KEY` are provided. | Fixed import-time crash when `openai` dependencies are missing and `--ai` is not used. |
| `reporting/pdf_exporter.py` | Converts HTML to PDF with `xhtml2pdf`, WeasyPrint fallback, or placeholder fallback. | `_resolve_css_vars()`, `_strip_incompatible_css()`, `_add_pdf_base_styles()`, `_preprocess_html_for_xhtml2pdf()`, `_export_with_xhtml2pdf()`, `_export_with_weasyprint()`, `_export_with_minimal_placeholder()`, `export_pdf()`. | `xhtml2pdf`, `weasyprint`. | Full PDF path now works after adding `xhtml2pdf` to requirements and environment. |
| `reporting/__init__.py` | Package marker for reporting modules. | None. | None. | No issues. |
| `templates/report_template.html` | Main HTML/PDF report template with cover page, summary, tables, module sections, and footer. | Jinja template only. | None directly. | Reworked for cover page, findings table, executive summary, baseline section, module sections, and repeated confidentiality footer. |

### Config and Documentation

| File | What it does | Notes |
|------|--------------|-------|
| `config.yaml` | Runtime defaults for timeouts, ports, sources, delay, and retries. | Updated to include HackerTarget in subdomain sources. |
| `requirements.txt` | Python dependency list. | Added `xhtml2pdf==0.2.17` for full PDF export. |
| `README.md` | End-user setup, usage, flags, output, pricing/contact placeholders. | Rewritten for current CLI and feature set. |
| `CONTRIBUTING.md` | Development workflow and validation guidance. | Existing contributor instructions. |
| `LEGAL.md` | Usage boundaries and legal disclaimer. | Existing legal guidance. |
| `LICENSE` | MIT license. | No issues. |
| `.gitignore` | Ignore rules for envs, outputs, logs, and generated artifacts. | Existing ignore rules. |

### Generated and Example Artifacts

These were read to verify current behavior and output shape:

- Root artifacts: `scan_data.json`, `structured_output.json`, `ai_report.json`, `final_report.html`, `final_report.pdf`, `final_report.json`
- Sample output folders: `deliverables/*`, `test_output/*`, `scan_history/example.com/*`, `output/*.json`, `output/*.html`, `output/*.pdf`, `output/sentinelx.log`

What they do:

- Store past scans, structured findings, example client deliverables, and previous report renders.

Known issues visible from artifacts/logs before fixes:

- Older logs showed prior versions sending full URLs into the `crt.sh` query.
- Older artifacts reflected an always-written `ai_report.json`, even when external AI was not requested.
- Older reports had a weaker executive summary and no rolling baseline comparison.

## Execution Flow

Entry point:

`main.py`

Phase flow:

1. Parse CLI arguments
2. Load YAML config
3. Normalize target domain
4. Run scoped collectors
5. Build structured findings
6. Build executive summary and module sections
7. Optionally compare against rolling baseline
8. Optionally generate AI narrative when `--ai` is set
9. Write JSON artifacts
10. Render HTML
11. Render PDF
12. Save scan history and rolling baseline

Output:

- `scan_data.json`
- `structured_output.json`
- `final_report.json` when `--format json|all`
- `final_report.html` when `--format html|pdf|all`
- `final_report.pdf` when `--format pdf|all`
- `ai_report.json` only when `--ai` is used

## Step 2: CLI Flag Reference

| Flag | Description | Module triggered | Output |
|------|-------------|-----------------|--------|
| `DOMAIN` | Positional target domain | `main.py` → full pipeline | Same as `--domain` |
| `-d`, `--domain` | Target domain | `main.py` → full pipeline | Same as positional domain |
| `--scope quick` | DNS + headers + SSL only | `core/scanner.py` scoped collectors | JSON/HTML/PDF per `--format` |
| `--scope standard` | All passive modules, no port scan | `core/scanner.py` | JSON/HTML/PDF per `--format` |
| `--scope deep` | All modules + port scan + brute-force subdomains | `core/scanner.py` | JSON/HTML/PDF per `--format` |
| `--format pdf` | Generate HTML and PDF report | `reporting/html_renderer.py`, `reporting/pdf_exporter.py` | `final_report.html`, `final_report.pdf` |
| `--format html` | Generate HTML report only | `reporting/html_renderer.py` | `final_report.html` |
| `--format json` | Generate report JSON only | `reporting/formatter.py` | `final_report.json` |
| `--format all` | Generate JSON, HTML, and PDF | reporting stack | all report artifacts |
| `--compare last` | Diff against rolling baseline and update it | `core/drift_tracker.py` | comparison data in structured/report output |
| `--ai` | Opt in to OpenAI-assisted narrative | `reporting/ai_generator.py` | `ai_report.json` |
| `--config PATH` | Load alternate config file | `core/runtime_config.py` | affects runtime behavior |
| `--output-dir PATH` | Choose output directory | `main.py` | writes artifacts to chosen path |
| `--delay-ms N` | Override request delay between outbound requests | `main.py` + collectors using `rate_limit_ms` | affects pacing, no direct artifact |
| `--analyst NAME` | Report metadata label | formatter/reporting | reflected in report metadata |
| `--assessment-type TEXT` | Report metadata label | formatter/reporting | reflected in report metadata |
| `--baseline` | Deprecated compatibility baseline save | `core/drift_tracker.py` | saves baseline, no diff |
| `--allow-external-ai` | Deprecated compatibility flag | none beyond parser compatibility | no longer required |
| `--no-pdf` | Deprecated compatibility flag | parser compatibility | rewrites `pdf` output choice to HTML |

Missing flags noted:

- No per-module include/exclude flags such as `--headers-only`, `--ports-only`, or `--subdomains-only`.
- No custom brute-force wordlist flag yet.

## Step 3: Correct Full Scan Sequence

Recommended full commercial scan:

```bash
python main.py --domain example.com --scope deep --compare last --ai --format all
```

Flag order explanation:

1. `--domain example.com`: choose the target
2. `--scope deep`: enable full scan depth, including ports and brute-force subdomains
3. `--compare last`: diff against the previous rolling baseline and update it
4. `--ai`: opt in to external OpenAI narrative generation if `OPENAI_API_KEY` exists
5. `--format all`: write JSON, HTML, and PDF outputs

Ideal output shape:

- Console summary with target, scope, format, duration, and output paths
- `scan_data.json` with raw DNS, TLS, headers, ports, favicon, tech, subdomains, and takeover data
- `structured_output.json` / `final_report.json` with findings, score, summary, module sections, and comparison data
- `final_report.html` with cover page, executive summary, findings table, module sections, and footer
- `final_report.pdf` containing the same rendered report in PDF form

## Step 4: Bug List

| Severity | File / Line | Bug | Fix |
|----------|-------------|-----|-----|
| HIGH | `reporting/ai_generator.py:117` | Optional AI path used to import `openai` at module load, crashing non-AI scans if optional transitive deps were missing. | Import `OpenAI` inside `generate_ai_report()` only when `--ai` is used. |
| HIGH | `main.py:47-61`, `main.py:176-202` | Missing `--scope`, `--format`, and `--compare last` support blocked required workflow. | Added scope, format, compare, and baseline handling in parser and main pipeline. |
| HIGH | `core/subdomain.py:113-208` | Subdomain enumeration relied on a single passive source and had no brute-force/de-dup improvement path. | Added HackerTarget fallback, passive brute-force list, and shared normalization. |
| HIGH | `core/headers.py:121-175` | Header transport failures needed explicit `UNKNOWN` status per header rather than implied absence. | Added per-header rows with PASS/WARN/FAIL/UNKNOWN and transport-aware handling. |
| HIGH | `reporting/formatter.py:218-241` | SPF/DMARC weaknesses were not converted into scored findings and executive summary impact. | Added DNS/email findings with severity mapping and remediation text. |
| MEDIUM | `core/dns_recon.py:133-149` | Needed explicit verification of `_dmarc.{domain}` lookup and DMARC policy parsing. | Kept `_dmarc` query and added parsed policy analysis. |
| MEDIUM | `core/subdomain.py:77-111` | Needed verification that `crt.sh` query was not double-encoding the domain. | Current source correctly uses `https://crt.sh/?q=%25.{domain}&output=json`. |
| MEDIUM | `core/favicon_hash.py:65-112` | Duplicate favicon hash key issue needed verification. | Current source already resolves this by using a distinct second hash key. |

## Implemented Now

- Fixed or verified all listed critical/high items from the request
- Added `--scope`, `--format`, `--compare last`, and `--delay-ms`
- Added HackerTarget fallback and passive brute-force subdomain candidates
- Added SPF/DMARC parsing and findings
- Added structured header scoring with PASS/WARN/FAIL/UNKNOWN
- Added founder-readable executive summary with top 3 urgent findings
- Added rolling baseline comparison feature
- Reworked HTML/PDF report layout and findings table
- Rewrote README for current functionality

## Verification Summary

### 1. `python main.py --domain google.com --scope quick --format json`

Status:

- Completed successfully

Observed output summary:

- Target: `google.com`
- Scope: `quick`
- DNS records returned successfully
- TLS grade evaluated as `A`
- JSON artifacts written: `scan_data.json`, `structured_output.json`, `final_report.json`

### 2. `python main.py --domain example.com --scope standard --format pdf`

Status:

- Completed successfully
- PDF generated through `xhtml2pdf`

Observed output summary:

- Target: `example.com`
- Scope: `standard`
- HTML report written to `final_report.html`
- PDF report written to `final_report.pdf`
- Executive summary confirmed in HTML source

Executive summary markers:

- `EXECUTIVE SUMMARY`
- `Top 3 Most Urgent Findings`
- `Remediation quotes available — contact [your email]`
