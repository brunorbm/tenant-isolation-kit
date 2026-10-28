# Contributing

Thank you for helping. Bug reports, new Semgrep rules and new seeded bugs are all welcome. A
seeded bug that one of the layers misses is especially useful.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" semgrep pre-commit
pre-commit install
```

## Before opening a pull request

Run the same checks as CI:

```bash
ruff format --check . && ruff check . && mypy
coverage run -m pytest && coverage report      # 95 % branch coverage floor
semgrep --metrics=off --test semgrep/
python scripts/render_bug_table.py --check
```

## Ground rules

- **Every claim is tested.** The README's seeded-bug table is generated from
  `examples/seeded_bugs.py`, and the tests check every cell in both directions. If you change
  what a layer catches, update the catalog, then run `python scripts/render_bug_table.py`.
- **Adding a Semgrep rule:**
  - put the rule in `semgrep/<id>.yaml`, with a test file `semgrep/<id>.py` next to it;
  - the test file needs `# ruleid:` cases for what the rule must catch and `# ok:` cases for
    the closest safe code;
  - fill in `metadata.cwe`, `owasp`, `confidence` and `tradeoffs` (the known false positives
    and false negatives);
  - the example fixed app must stay at zero findings.
- **Adding a seeded bug:**
  - add it to `vulnerable_app`, with a `SEEDED BUG Vn` comment;
  - add its fix to `fixed_app`, with a `FIX Vn` comment;
  - add an entry to `SEEDED_BUGS`;
  - add an exploit to `tests/test_seeded_bugs.py`.
- **The guard fails closed.** If a change could make a statement run unscoped, it needs a
  test that shows it cannot.
- Typing is `mypy --strict`. Lint is ruff with the bandit (`S`) rules. Avoid `# noqa` and
  `# type: ignore`; when one is needed, add a comment explaining why.
- Use small, conventional commits (`feat(guard): ...`, `fix(semgrep): ...`, `docs: ...`).

## Reporting security issues

Please do not open public issues for bypasses. See [SECURITY.md](SECURITY.md).
