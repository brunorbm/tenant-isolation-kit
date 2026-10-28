"""Render the seeded-bug table of README.md from ``examples/seeded_bugs.py``.

python scripts/render_bug_table.py          # rewrite README.md in place
python scripts/render_bug_table.py --check  # exit 1 if README.md is stale (CI)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from examples.seeded_bugs import SEEDED_BUGS, SeededBug  # noqa: E402

README = ROOT / "README.md"
START = "<!-- seeded-bugs:start -->"
END = "<!-- seeded-bugs:end -->"
YES, NO = "caught", "-"


def _semgrep(bug: SeededBug) -> str:
    return "<br>".join(f"`{rule}`" for rule in bug.semgrep) or NO


def render() -> str:
    lines = [
        "| Bug | Route | Flaw | CWE | Semgrep | Matrix | Guard (strict) |",
        "|---|---|---|---|---|---|---|",
    ]
    lines += [
        f"| {b.id} | `{b.route}` | {b.summary} | {b.cwe} | {_semgrep(b)} "
        f"| {YES if b.matrix else NO} | {YES if b.guard else NO} |"
        for b in SEEDED_BUGS
    ]
    return "\n".join(lines)


def splice(readme: str, table: str) -> str:
    head, sep, rest = readme.partition(START)
    _, sep2, tail = rest.partition(END)
    if not sep or not sep2:
        raise SystemExit(f"README.md must contain {START} and {END}")
    return f"{head}{START}\n{table}\n{END}{tail}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--check", action="store_true", help="fail if README.md is stale")
    args = parser.parse_args(argv)
    current = README.read_text(encoding="utf-8")
    updated = splice(current, render())
    if args.check:
        if updated != current:
            print("README.md seeded-bug table is stale; run scripts/render_bug_table.py")
            return 1
        return 0
    README.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
