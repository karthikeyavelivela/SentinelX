# SentinelX

SentinelX is a Python CLI that scans an internet-facing domain for visible security exposure and turns the results into founder-friendly and engineer-ready reports.

## What it does

SentinelX runs a sequential 7-phase pipeline:

| Phase | What it does |
|---|---|
| 1 · Attack Surface Discovery | Subdomain enumeration, live host checks, port scanning, tech fingerprinting |
| 2 · Web & API Enumeration | HTML crawling, JS endpoint extraction, API surface mapping |
| 3 · Access Control Testing | IDOR checks, auth bypass, HTTP method abuse |
| 4 · Injection Testing | SQLi, XSS, open redirect detection |
| 5 · Misconfiguration Testing | CORS, missing security headers, debug exposure, unsafe methods |
| 6 · Risk Scoring | CVSS-style scoring, severity mapping, business impact enrichment |
| 7 · Report Generation | Structured HTML + PDF output with all findings |

The project is designed for non-destructive assessment and produces a unified finding schema that flows into risk scoring and reporting.

## Supported checks

- Certificate transparency discovery through crt.sh
- DNS record collection, including explicit _dmarc.<domain> lookups
- TLS certificate metadata collection
- HTTPS response header inspection
- Lightweight TCP exposure checks on a configurable port list
- Favicon hashing and scored technology fingerprinting
- Subdomain takeover heuristics for known dangling CNAME providers
- Drift tracking across repeated scans for the same domain
- Deterministic reporting, with explicit opt-in support for OpenAI-assisted narrative generation

## Who It Is For

- Security consultants delivering external exposure audits
- Founders who need a plain-English risk summary
- Engineering teams that want repeatable baseline comparisons

## Install

```bash
pip install -r requirements.txt
```

Recommended local setup:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py -d target.com
```

> Only test domains you own or are explicitly authorized to assess.

## Configuration

Default runtime settings live in [config.yaml](config.yaml). You can point SentinelX at an alternate file with --config.

## Quick Start

```bash
python main.py --domain yourdomain.com
```

The first scan of any domain asks you to confirm authorization in the terminal before it touches the network — see [Authorization Gate](#authorization-gate).

## GUI

A desktop front-end is available for people who don't want the CLI:

```bash
python gui.py
```

It collects the target domain, your contact email (used for the report's closing line, no password field anywhere), and an authorization checkbox, then runs the same main.py pipeline underneath and streams the log live.

## What SentinelX Checks

- DNS records and email protections: A, MX, TXT, SPF, DMARC
- TLS certificate reachability and expiry
- Security headers on the public site
- Passive subdomain discovery from crt.sh and HackerTarget
- Optional passive brute-force subdomain discovery in deep scans
- Publicly reachable common TCP ports in deep scans
- Favicon fingerprinting and basic tech hints
- Subdomain takeover patterns
- Baseline drift with --compare last

## Scan Depth

- quick: DNS + headers + SSL only
- standard: all modules except port scan and brute-force subdomains
- deep: all modules, plus port scan and brute-force subdomains

## Full Flag Reference

| Flag | Description | Notes |
|------|-------------|-------|
| DOMAIN | Positional target domain | Optional if --domain is used |
| -d, --domain | Target domain | Accepts hostname like example.com |
| --scope [quick|standard|deep] | Sets scan depth | Default: standard |
| --format [pdf|html|json|all] | Sets output format | Default: pdf |
| --compare last | Compare against rolling baseline | Saves baseline in .sentinelx/ |
| --ai | Opt in to OpenAI-assisted narrative output | Requires OPENAI_API_KEY |
| --config PATH | Load alternate YAML config | Default: config.yaml |
| --output-dir PATH | Directory for generated artifacts | Default: current directory |
| --delay-ms N | Delay between outbound requests in milliseconds | Overrides config value |
| --analyst NAME | Analyst name in report metadata | Optional |
| --analyst-email EMAIL | Contact email shown in the report's closing line | Optional; falls back to generic text if omitted |
| --assessment-type TEXT | Assessment label in report metadata | Optional |
| --i-have-authorization | Skip the interactive authorization prompt | For CI/non-interactive use; the GUI sets this itself |
| --baseline | Deprecated compatibility flag | Saves a fresh baseline |
| --no-pdf | Deprecated compatibility flag | Prefer --format html or json |

## Authorization Gate

Every scan of a new domain requires explicit confirmation before any network request is made:

```text
SentinelX - Authorization Required
Target: example.com

SentinelX performs active checks (HTTP fetches, TCP port probes) against
the target, not only passive lookups. You must own this domain or hold
explicit written authorization to assess it. See LEGAL.md for the full
authorization and legal-compliance requirements.

Type "yes" to confirm authorization and continue:
```

Acknowledgment is cached per-domain in .sentinelx/consent.json, so repeat scans of the same domain don't reprompt. Use --i-have-authorization to skip the prompt entirely for scripted/CI runs — you are still asserting the same authorization by passing it.

## Correct Full Scan Command

Standard recurring audit:

```bash
python main.py --domain example.com --scope deep --compare last --format all --analyst-email you@example.com
```

Non-interactive (CI, cron, already-authorized scripted runs):

```bash
python main.py --domain example.com --scope deep --compare last --format all --i-have-authorization
```

With AI narrative enabled:

```bash
python main.py --domain example.com --scope deep --compare last --ai --format all
```

What each flag does:

- --domain example.com: target to assess
- --scope deep: enables all scan modules, including port scan and brute-force subdomains
- --compare last: diffs against the last saved baseline and then updates it
- --ai: opts in to OpenAI-generated narrative text if the API key exists
- --format all: writes JSON, HTML, and PDF outputs
- --analyst-email: fills the report's closing contact line instead of generic text
- --i-have-authorization: skips the interactive confirmation prompt (see Authorization Gate)

## Ideal Output

SentinelX writes:

- scan_data.json: raw collector output
- structured_output.json: normalized findings and scoring
- final_report.json: report-grade JSON when --format json|all
- final_report.html: styled report when --format html|pdf|all
- final_report.pdf: PDF report when --format pdf|all
- ai_report.json: optional AI narrative only when --ai is used

The ideal report includes:

- A cover page with the domain, date, and overall risk score
- A plain-English executive summary
- A findings table with severity, module, and fix
- Per-module sections for DNS, headers, TLS, ports, subdomains, and takeover signals
- A baseline comparison section when --compare last is used

## Report Sections Explained

- Executive Summary: plain-English overview for non-technical readers
- Findings Table: one-line list of the most important issues and fixes
- Module Sections: deeper evidence grouped by scan area
- Baseline Comparison: what changed since the last saved scan
- Technical Appendix: raw supporting details such as DNS, TLS, and ports

## Sample Output Layout

```text
┌───────────────────────────────────────────────┐
│ SentinelX Report                             │
│ example.com                                  │
│ 72/100 HIGH                                  │
├───────────────────────────────────────────────┤
│ EXECUTIVE SUMMARY                            │
│ - 3 critical findings                        │
│ - 7 high findings                            │
│ - 14 subdomains discovered                   │
│ - 4 open ports                               │
├───────────────────────────────────────────────┤
│ FINDINGS TABLE                               │
│ High   Missing DMARC      dns      Publish   │
│ High   Port 3306 Exposed  ports    Restrict  │
├───────────────────────────────────────────────┤
│ MODULE SECTIONS                              │
│ DNS | HEADERS | TLS | SUBDOMAINS | PORTS     │
└───────────────────────────────────────────────┘
```

## Configuration

Default settings live in config.yaml.

Supported settings:

- timeouts.http
- timeouts.dns
- timeouts.tcp
- ports
- user_agent
- subdomain_sources
- rate_limit_ms
- max_retries

## Pricing

Professional audit service — contact [email] for a quote.

## License

MIT. See LICENSE.

## Contact

For questions or audit requests, use the repository contact channels.

├── phase5_misconfiguration.json
├── risk_scored_findings.json
└── final_report.html / final_report.pdf
```

Repeated runs also create per-domain history snapshots under scan_history/<domain>/.

## Current scope and limitations

SentinelX is built for learning and non-destructive assessment, not adversarial exploitation:

- CVSS mapping is static and type-based (not context-aware)
- IDOR checks are path-pattern heuristics, not object-level enumeration
- Injection detection is intentional breadth-first, not depth exploitation
- No persistence layer — scans don't resume
- Auth handling is limited to session-based flows

## Current architecture

- main.py
  - Parses CLI flags, loads config, runs the scan pipeline, and manages output artifacts.
- core/scanner.py
  - Normalizes the target domain and orchestrates collection phases with isolated error handling.
- core/subdomain.py
  - Enumerates candidate subdomains and validates them through A, AAAA, or CNAME resolution.
- core/dns_recon.py
  - Collects A, MX, TXT, CNAME, SPF, and DMARC data.
- core/ssl_analysis.py
  - Pulls external TLS metadata from port 443.
- core/headers.py
  - Checks for recommended HTTP security headers without inflating findings on transport failure.
- core/port_check.py
  - Performs configurable lightweight TCP exposure checks.
- core/favicon_hash.py
  - Fetches and hashes favicons for known fingerprint matching.
- core/techstack.py
  - Uses scored signatures with confidence levels for technology inference.
- core/takeover.py
  - Flags potential subdomain takeover conditions from dangling CNAME patterns.
- core/drift_tracker.py
  - Compares current scan results with the most recent historical snapshot.
- reporting/formatter.py
  - Converts collector output into findings, attack-surface summaries, and exposure scoring.
- reporting/ai_generator.py
  - Produces deterministic or explicit-opt-in OpenAI-assisted narrative output.
- reporting/html_renderer.py
  - Renders the HTML report.
- reporting/pdf_exporter.py
  - Converts HTML to PDF and reports whether the result is full, placeholder, or skipped.

## Built by

[Karthikeya Velivela](https://github.com/karthikeyavelivela) — AppSec Engineer @ PETZU · Active on HackerOne (karthikeyavelivela) · B.Tech CSE, KL University '27

Also see: [LLM Red Team Framework](https://github.com/karthikeyavelivela/llm-redteam) — automated OWASP LLM Top 10 testing CLI

## License

MIT — use it, extend it, don't test systems you don't own.


1. Run SentinelX against authorized client scope.
2. Review `structured_output.json` for findings, drift information, and collection quality.
3. Deliver `final_report.html` and, when applicable, `final_report.pdf`.

## Legal notice

Use SentinelX only on infrastructure you own or where you have written authorization to assess. Unauthorized testing can violate law and contractual obligations.
>>>>>>> ff06bdd (chore: remove all historical dead attack modules, align repo to v2 passive recon architecture)
=======
- Product and remediation quote placeholder: `[your email]`
>>>>>>> 21e24ac ( new version)
