# Contributing to ELFscope

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
```

Run checks:

```bash
make check
```

## Code principles

- Keep the parser read-only. Do not add execution, patching, persistence, or process-injection features to the core utility.
- Prefer observations with evidence over categorical conclusions.
- Keep output deterministic so JSON can be compared in version control.
- Add a test for every new parsing rule or signal.
- Keep external dependencies small and available in mainstream Linux repositories when practical.
- Document heuristic thresholds and limitations.

## Pull requests

A good change should include a concise description, tests, documentation updates when the output model changes, and a note about false-positive behaviour for new heuristics.
