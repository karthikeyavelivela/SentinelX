# Contributing to SentinelX

Thanks for contributing to SentinelX.

## Development setup

1. Fork and clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Branching

- Create a focused branch per change.
- Keep pull requests scoped and reviewable.

## Coding guidelines

- Preserve current module boundaries (`core/`, `reporting/`, `templates/`).
- Keep scanners resilient: one collector failure must not crash the pipeline.
- Keep finding schema stable in `reporting/formatter.py`.
- Avoid introducing intrusive checks unless explicitly approved by project owners.

## Validation before PR

Run:

```bash
python -m compileall .
python main.py example.com --i-have-authorization
python main.py -d example.com --no-pdf --output-dir ./test_output --i-have-authorization
```

`--i-have-authorization` skips the interactive authorization prompt so these
commands run unattended; only use it against domains you're actually cleared
to scan (see `LEGAL.md`).

## Commit messages

- Use clear imperative subject lines.
- Example: `refactor: isolate scanner collectors and add data quality reporting`

## Security and legal expectations

SentinelX is for authorized assessment only.  
Do not add destructive or unauthorized testing behavior.
