# Contributing to SentinelX

Thanks for your interest in improving SentinelX.

## Development setup

1. Fork and clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Branching

- Create a focused feature/fix branch from the default branch.
- Keep pull requests small and scoped to one concern when possible.

## Coding guidelines

- Follow existing module boundaries (`recon`, `web`, `attacks`, `risk`, `reporting`, etc.).
- Prefer readable, composable functions over monolithic logic.
- Keep new checks non-destructive and safe by default.
- Reuse shared helpers/utilities before introducing duplicates.
- Preserve output schema consistency for findings to avoid breaking scoring/reporting.

## Testing and validation

Before opening a PR, run the checks you can in your environment:

```bash
python -m compileall .
```

Also run a quick scan against an authorized/local target where possible:

```bash
python main.py -d example.com
```

## Commit messages

- Use clear, imperative commit messages.
- Example: `docs: add contributor guide and refresh project README`

## Pull requests

Include:

- What changed
- Why it changed
- Any validation commands run
- Follow-up work or known limitations (if relevant)

## Security and legal expectations

SentinelX is for authorized testing and education.

Do not submit code that enables destructive exploitation or unsafe defaults.
