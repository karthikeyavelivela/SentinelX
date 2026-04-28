# SentinelX

SentinelX is a Python CLI for external exposure intelligence. It performs passive and low-impact reconnaissance against an authorized target domain, then produces structured JSON output and consulting-ready HTML or PDF reporting.

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

## What SentinelX does not do

- No exploit execution
- No credential brute force
- No authenticated application testing
- No payload-based SQLi, XSS, IDOR, auth bypass, or CORS exploitation logic

## Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py -d target.com
```

> Only test domains you own or are explicitly authorized to assess.

## Configuration

Default runtime settings live in [config.yaml](config.yaml). You can point SentinelX at an alternate file with --config.

Configurable values include:

- HTTP, DNS, and TCP timeouts
- TCP port list
- User-Agent
- Subdomain data sources
- Rate limiting delay
- Retry count

## CLI usage

Basic usage:

```bash
python main.py example.com
python main.py -d example.com
```

Common options:

```bash
python main.py example.com --no-pdf
python main.py example.com --config ./config.yaml
python main.py example.com --baseline
python main.py example.com --ai openai --allow-external-ai
```

## Output

Each run produces JSON artifacts plus a final report:

```text
output/
├── assets.json
├── endpoints.json
├── phase3_access_control.json
├── phase4_injection.json
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
