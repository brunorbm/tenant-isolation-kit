"""pytest plugin: one cross-tenant test per (route, attack), generated from the app.

Registered automatically through the ``pytest11`` entry point. Usage::

    NOTES = Resource(name="note", collection="/notes", create=lambda c: {"body": c})

    @pytest.mark.tenant_matrix(app=app, resources=[NOTES])
    def test_cross_tenant(cross_tenant_case, tenant_pair):
        cross_tenant_case.check(tenant_pair)

``tenant_pair`` is a fixture you provide: a :class:`~tenant_isolation_kit.TenantPair`
holding two clients authenticated as two different tenants. Pass ``routes=`` instead
of ``app=`` to give the route list explicitly.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from tenant_isolation_kit.matrix import Case, Resource, Route, build_cases, discover_routes

MARKER = "tenant_matrix"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        f"{MARKER}(app=None, routes=None, resources=()): generate one cross-tenant case "
        "per route and attack; the test receives it as the `cross_tenant_case` fixture.",
    )


def cases_for_marker(marker: pytest.Mark) -> list[Case]:
    """Build the cases described by a ``tenant_matrix`` marker."""
    if marker.args:
        raise pytest.UsageError(f"@pytest.mark.{MARKER} takes keyword arguments only")
    app: Any = marker.kwargs.get("app")
    routes: Iterable[Route] | None = marker.kwargs.get("routes")
    resources: Iterable[Resource] = marker.kwargs.get("resources", ())
    if (app is None) == (routes is None):
        raise pytest.UsageError(f"@pytest.mark.{MARKER} needs exactly one of app= or routes=")
    resolved = discover_routes(app) if routes is None else list(routes)
    cases = build_cases(resources, resolved)
    if not cases:
        raise pytest.UsageError(
            f"@pytest.mark.{MARKER} produced no cases: no route lives under the "
            "collections of the given resources"
        )
    return cases


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    marker = metafunc.definition.get_closest_marker(MARKER)
    if marker is None:
        return
    if "cross_tenant_case" not in metafunc.fixturenames:
        raise pytest.UsageError(
            f"{metafunc.definition.nodeid}: @pytest.mark.{MARKER} needs the "
            "`cross_tenant_case` fixture in the test signature"
        )
    cases = cases_for_marker(marker)
    metafunc.parametrize("cross_tenant_case", cases, ids=[c.id for c in cases], indirect=True)


@pytest.fixture
def cross_tenant_case(request: pytest.FixtureRequest) -> Case:
    """The :class:`~tenant_isolation_kit.matrix.Case` generated for this test item."""
    case: Case | None = getattr(request, "param", None)
    if case is None:
        raise pytest.UsageError(
            f"`cross_tenant_case` is only available to tests marked @pytest.mark.{MARKER}"
        )
    return case
