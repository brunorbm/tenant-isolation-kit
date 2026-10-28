"""The Semgrep rules against the example apps, checked against the bug catalog."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from examples.seeded_bugs import SEEDED_BUGS

ROOT = Path(__file__).resolve().parents[1]
# Prefer the semgrep installed next to this interpreter (an unactivated virtualenv).
SEMGREP = shutil.which("semgrep", path=str(Path(sys.executable).parent)) or shutil.which("semgrep")
pytestmark = pytest.mark.skipif(SEMGREP is None, reason="semgrep is not installed")


def scan(target: Path) -> list[tuple[str, int]]:
    """(rule id, line) of every finding of the kit's rules in ``target``."""
    assert SEMGREP is not None
    completed = subprocess.run(
        [SEMGREP, "scan", "--metrics=off", "--quiet", "--json", "--config", "semgrep", str(target)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    )
    results = json.loads(completed.stdout)["results"]
    return [(r["check_id"].rsplit(".", 1)[-1], r["start"]["line"]) for r in results]


def handler_at(source: Path, line: int) -> str:
    """Name of the innermost function that contains ``line``."""
    best: ast.FunctionDef | None = None
    for node in ast.walk(ast.parse(source.read_text())):
        if (
            isinstance(node, ast.FunctionDef)
            and node.lineno <= line <= (node.end_lineno or node.lineno)
            and (best is None or node.lineno > best.lineno)
        ):
            best = node
    assert best is not None, f"finding at line {line} is outside any function"
    return best.name


def test_rules_fire_exactly_where_the_catalog_says() -> None:
    source = ROOT / "examples" / "vulnerable_app" / "main.py"
    found = {(handler_at(source, line), rule) for rule, line in scan(source)}
    expected = {(bug.handler, rule) for bug in SEEDED_BUGS for rule in bug.semgrep}
    assert found == expected


def test_fixed_app_has_no_findings() -> None:
    assert scan(ROOT / "examples" / "fixed_app" / "main.py") == []
