# SentinelX

SentinelX is an automated **Attack Surface Intelligence Framework** built as a Python CLI. Point it at a target domain, and it runs a phased pipeline to discover assets, enumerate exposed functionality, test for common weaknesses, score risk, and generate a report.

```bash
python main.py -d example.com
```

> SentinelX is designed as a learning-focused, production-style AppSec project: modular architecture, repeatable phases, and structured findings.

---

## What SentinelX does

SentinelX runs a **7-phase pipeline**:

1. **Attack Surface Discovery**
   - Subdomain enumeration
   - Live host checks
   - Port scanning
   - Technology fingerprinting
2. **Web & API Enumeration**
   - HTML crawling
   - JavaScript endpoint extraction
   - Endpoint normalization/mapping
3. **Access Control Testing**
   - IDOR checks
   - Auth bypass checks
   - HTTP method abuse checks
4. **Injection Testing**
   - SQLi checks
   - XSS checks
   - Open redirect checks
5. **Security Misconfiguration Testing**
   - CORS checks
   - Missing security headers
   - Debug exposure
   - Unsafe method exposure
6. **Risk Scoring**
   - CVSS-style scoring
   - Severity mapping
   - Business impact enrichment
7. **Report Generation**
   - HTML report
   - PDF report

---

## Architecture highlights

- **Modular, plugin-style structure**: each phase is implemented in focused modules.
- **Async concurrency for recon**: parallel host checks through an async engine and semaphore control.
- **Fallback-first recon approach**: recon components degrade gracefully when external binaries are missing.
- **Centralized config**: runtime values (timeouts, concurrency, headers) are loaded from config/env.
- **Unified finding schema**: downstream risk scoring/reporting consumes standardized findings.

---

## Project structure

```text
.
├── main.py
├── requirements.txt
├── core/
│   ├── engine.py
│   ├── config.py
│   └── logger.py
├── recon/
│   ├── subdomain_enum.py
│   ├── live_hosts.py
│   ├── port_scan.py
│   └── tech_detect.py
├── web/
│   ├── crawler.py
│   ├── js_parser.py
│   └── api_mapper.py
├── attacks/
│   ├── vuln_engine.py
│   ├── idor.py
│   ├── auth_bypass.py
│   ├── method_tester.py
│   ├── jwt_analyzer.py
│   ├── injection/
│   │   ├── engine.py
│   │   ├── sqli.py
│   │   ├── xss.py
│   │   └── open_redirect.py
│   └── config/
│       ├── engine.py
│       ├── cors.py
│       ├── headers.py
│       ├── debug.py
│       └── methods.py
├── risk/
│   ├── engine.py
│   ├── scorer.py
│   ├── cvss.py
│   ├── severity.py
│   └── impact.py
├── reporting/
│   ├── report_builder.py
│   └── templates/
│       └── report.html
├── auth/
│   ├── session.py
│   └── juice_shop_auth.py
├── utils/
│   ├── banner.py
│   ├── request_utils.py
│   ├── progress.py
│   ├── global_progress.py
│   ├── timer.py
│   └── helpers.py
├── output/
└── reports/
```

---

## Installation

### 1) Clone

```bash
git clone <your-fork-or-repo-url>
cd SentinelX
```

### 2) Create environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3) Install dependencies

```bash
pip install -r requirements.txt
```

### 4) Configure environment (optional but recommended)

Create a `.env` file in the repository root for runtime tuning (timeouts, concurrency, user-agent, etc.).

---

## Usage

Run a full scan:

```bash
python main.py -d example.com
```

Notes:
- If the domain is provided without a scheme, SentinelX prepends `https://`.
- Outputs are saved as JSON artifacts used by risk scoring and reporting.

---

## Output artifacts

Typical generated files include:

- `assets.json`
- `endpoints.json`
- `phase3_access_control.json`
- `phase4_injection.json`
- `phase5_misconfiguration.json`
- `all_findings_raw.json`
- `risk_scored_findings.json`

Reports are generated in HTML/PDF format via the reporting phase.

---

## Strengths

- End-to-end single-command workflow
- Clear modular layout for extension
- Async recon improves speed for host checks
- Professional-style outputs and reporting
- Built-in risk scoring flow
- Non-destructive, logic-based checks

## Current limitations

- CVSS mapping is static and type-based
- IDOR checks are path-pattern oriented and shallow
- Auth bypass heuristics can produce false positives
- Authentication/session handling is limited
- Phases 3–5 are largely synchronous loops
- Injection detection depth is intentionally basic
- No persistence layer for resumable scans

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow, style, testing, and pull request expectations.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

---

## Legal notice

Use SentinelX only on systems you own or are explicitly authorized to test.

Unauthorized security testing may be illegal. You are responsible for complying with all applicable laws and policies.
