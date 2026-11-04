# tripline

Sigma detection rules handled as code: validated, tested against logs, and converted to
Microsoft Sentinel KQL and Splunk SPL in CI.

**Status: work in progress.** This repo is being built step by step; no rules are in it yet.
The full README (results, rule table, coverage layer) arrives once the rules and tests exist.

## Run it locally

Requires Python 3.12.

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"   # Windows: .venv\Scripts\pip
pytest
```

## Licences

- Code: MIT ([LICENSE](LICENSE))
- Detection rules in `rules/`: Detection Rule License 1.1 ([rules/LICENSE](rules/LICENSE))
- Third-party data and derived rules: see [NOTICE](NOTICE)
