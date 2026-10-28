"""The pytest plugin, exercised through pytester in-process runs."""

from __future__ import annotations

import pytest

HEADER = """
import pytest
from tenant_isolation_kit import Resource, Route

NOTES = Resource("note", "/notes", create=lambda c: {"body": c})
ROUTES = [Route("/notes", "GET"), Route("/notes/{id}", "GET")]
"""


def run(pytester: pytest.Pytester, body: str) -> pytest.RunResult:
    pytester.makepyfile(HEADER + body)
    return pytester.runpytest_inprocess("-p", "no:cacheprovider", "--collect-only", "-q")


def test_marker_generates_one_item_per_case(pytester: pytest.Pytester) -> None:
    result = run(
        pytester,
        """
@pytest.mark.tenant_matrix(routes=ROUTES, resources=[NOTES])
def test_isolation(cross_tenant_case):
    pass
""",
    )
    result.stdout.fnmatch_lines(
        [
            "*test_isolation[[]note:list:GET /notes[]]",
            "*test_isolation[[]note:read:GET /notes/{id}[]]",
        ]
    )
    assert result.ret == 0


def test_marker_is_registered(pytester: pytest.Pytester) -> None:
    result = pytester.runpytest_inprocess("--markers")
    result.stdout.fnmatch_lines(["@pytest.mark.tenant_matrix(*"])


@pytest.mark.parametrize(
    ("marker", "message"),
    [
        ("tenant_matrix(ROUTES, resources=[NOTES])", "takes keyword arguments only"),
        ("tenant_matrix(resources=[NOTES])", "needs exactly one of app= or routes="),
        ("tenant_matrix(app=object(), routes=ROUTES)", "needs exactly one of app= or routes="),
        ("tenant_matrix(routes=[Route('/x', 'GET')], resources=[NOTES])", "produced no cases"),
    ],
)
def test_marker_usage_errors(pytester: pytest.Pytester, marker: str, message: str) -> None:
    result = run(
        pytester, f"\n@pytest.mark.{marker}\ndef test_isolation(cross_tenant_case):\n    pass\n"
    )
    assert result.ret != 0
    assert message in result.stdout.str() + result.stderr.str()


def test_marker_without_fixture_is_an_error(pytester: pytest.Pytester) -> None:
    result = run(
        pytester,
        """
@pytest.mark.tenant_matrix(routes=ROUTES, resources=[NOTES])
def test_isolation():
    pass
""",
    )
    assert result.ret != 0
    assert "needs the `cross_tenant_case` fixture" in result.stdout.str() + result.stderr.str()


def test_fixture_without_marker_is_an_error(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(HEADER + "\ndef test_isolation(cross_tenant_case):\n    pass\n")
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*only available to tests marked @pytest.mark.tenant_matrix*"])
