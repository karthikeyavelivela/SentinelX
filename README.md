# SentinelX

**Automated attack surface intelligence. One command. Seven phases. PDF report.**

```bash
python main.py -d target.com
```

Point SentinelX at a domain. It enumerates subdomains, crawls endpoints, tests access controls, runs injection checks, scores every finding with CVSS-style severity, and generates a structured HTML/PDF report — without touching anything manually.

Built as a production-style Python CLI for real AppSec workflows, not a toy script.

---

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

Every finding flows through a unified schema into risk scoring and reporting. One run, one report.

---

## Architecture

```
SentinelX/
├── main.py                  # Entry point, pipeline orchestration
├── core/                    # Engine, config, logger
├── recon/                   # Subdomain enum, live hosts, port scan, tech detect
├── web/                     # Crawler, JS parser, API mapper
├── attacks/
│   ├── idor.py              # Access control checks
│   ├── auth_bypass.py
│   ├── injection/           # SQLi, XSS, open redirect engines
│   └── config/              # CORS, headers, debug, method checks
├── risk/                    # CVSS scoring, severity, impact enrichment
├── reporting/               # HTML/PDF report builder
└── utils/                   # Request utils, progress, helpers
```

Design decisions worth noting:
- **Async recon** — parallel host checks with semaphore control for speed without hammering targets
- **Fallback-first** — recon degrades gracefully when external binaries (subfinder, httpx) are missing
- **Unified finding schema** — all phases emit the same structure so risk scoring and reporting are decoupled from detection logic
- **Centralized config** — timeouts, concurrency, headers all tunable from env/config without touching module code

---

## Quick start

```bash
git clone https://github.com/karthikeyavelivela/SentinelX
cd SentinelX
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py -d target.com
```

> Only test domains you own or are explicitly authorized to assess.

---

## Output

Each run produces JSON artifacts per phase plus a final report:

```
output/
├── assets.json
├── endpoints.json
├── phase3_access_control.json
├── phase4_injection.json
├── phase5_misconfiguration.json
├── risk_scored_findings.json
└── final_report.html / final_report.pdf
```

---

## Current scope and limitations

SentinelX is built for learning and non-destructive assessment, not adversarial exploitation:

- CVSS mapping is static and type-based (not context-aware)
- IDOR checks are path-pattern heuristics, not object-level enumeration
- Injection detection is intentional breadth-first, not depth exploitation
- No persistence layer — scans don't resume
- Auth handling is limited to session-based flows

Contributions that extend depth without breaking the modular pipeline are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Built by

[Karthikeya Velivela](https://github.com/karthikeyavelivela) — AppSec Engineer @ PETZU · Active on HackerOne (`karthikeyavelivela`) · B.Tech CSE, KL University '27

Also see: [LLM Red Team Framework](https://github.com/karthikeyavelivela/llm-redteam) — automated OWASP LLM Top 10 testing CLI

---

## License

MIT — use it, extend it, don't test systems you don't own.
