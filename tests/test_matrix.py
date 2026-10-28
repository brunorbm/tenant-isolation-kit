"""Unit tests of the matrix: case generation, setup errors and finding messages."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from starlette.routing import Mount

from tenant_isolation_kit import Resource, Route, build_cases, discover_routes
from tenant_isolation_kit.matrix import IsolationFailure, MatrixSetupError, VacuousCaseError
from tests.helpers import NOTES, pair_for


def toy_app(*, create_status: int = 201, echo: bool = True, leaky_list: bool = False) -> FastAPI:
    """A one-resource app whose behaviour each test bends a little."""
    app = FastAPI()
    store: dict[int, dict[str, Any]] = {}

    @app.post("/things", status_code=create_status)
    def create(payload: dict[str, Any]) -> dict[str, Any]:
        thing = {"id": len(store) + 1, **(payload if echo else {})}
        store[thing["id"]] = thing
        return thing

    @app.get("/things")
    def listing() -> list[dict[str, Any]]:
        return list(store.values()) if leaky_list else []

    @app.get("/things/{thing_id}/raw")
    def raw(thing_id: int) -> dict[str, Any]:
        if thing_id not in store:
            raise HTTPException(status_code=404)
        return store[thing_id]

    app.router.routes.append(Mount("/static", app=FastAPI()))
    return app


THINGS = Resource("thing", "/things", create=lambda c: {"label": c})


def test_discover_routes_keeps_http_routes_only() -> None:
    routes = discover_routes(toy_app())
    assert Route("/things", "POST") in routes
    assert all(r.path != "/static" for r in routes)
    assert all(r.method in {"GET", "POST", "PUT", "PATCH", "DELETE"} for r in routes)
    assert routes == sorted(routes)


def test_build_cases_kinds_and_exclusions() -> None:
    routes = [
        Route("/notes", "GET"),
        Route("/notes", "POST"),
        Route("/notes/bulk", "POST"),
        Route("/notes/{id}", "GET"),
        Route("/notes/{id}", "DELETE"),
        Route("/notesmith", "GET"),
        Route("/other", "GET"),
    ]
    ids = [c.id for c in build_cases([NOTES], routes)]
    assert ids == [
        "note:list:GET /notes",
        "note:forge-query:GET /notes",
        "note:forge-body:POST /notes",
        "note:write:DELETE /notes/{id}",
        "note:read:GET /notes/{id}",
    ]
    no_forge = Resource("note", "/notes/", create=NOTES.create, exclude=[("GET", "/notes/{id}")])
    assert [c.kind for c in build_cases([no_forge], routes)] == ["list", "write"]


def test_create_failure_is_a_setup_error() -> None:
    (case,) = build_cases([THINGS], [Route("/things/{thing_id}/raw", "GET")])
    app = toy_app()

    @app.middleware("http")
    async def refuse_writes(request: Any, call_next: Any) -> Any:
        from starlette.responses import Response

        if request.method == "POST":
            return Response(status_code=422)
        return await call_next(request)

    with pytest.raises(
        MatrixSetupError, match=r"could not create thing \(POST /things -> HTTP 422"
    ):
        case.run(pair_for(app))


def test_missing_path_field_is_a_setup_error() -> None:
    resource = Resource("thing", "/things", create=lambda c: {"label": c}, id_field="uuid")
    (case,) = build_cases([resource], [Route("/things/{thing_id}/raw", "GET")])
    with pytest.raises(MatrixSetupError, match=r"no field 'uuid' for path parameter \{thing_id\}"):
        case.run(pair_for(toy_app()))


def test_owner_blind_case_is_vacuous() -> None:
    (case,) = build_cases([THINGS], [Route("/things", "GET")])
    with pytest.raises(VacuousCaseError, match="does not see its canary"):
        case.run(pair_for(toy_app()))


def test_leaky_list_fails_with_a_readable_message() -> None:
    (case,) = build_cases([THINGS], [Route("/things", "GET")])
    with pytest.raises(IsolationFailure) as excinfo:
        case.check(pair_for(toy_app(leaky_list=True)))
    assert str(excinfo.value) == (
        "cross-tenant access in thing:list:GET /things:\n"
        "  - tenant B's response to GET /things contains tenant A's data"
    )
    assert excinfo.value.findings[0].case_id == case.id


def test_write_without_item_route_checks_status_only() -> None:
    app = toy_app()

    @app.put("/things/{thing_id}/raw")
    def overwrite(thing_id: int) -> dict[str, str]:
        return {"status": "ok"}

    (case,) = build_cases([THINGS], [Route("/things/{thing_id}/raw", "PUT")])
    findings = case.run(pair_for(app))
    assert [f.message for f in findings] == [
        "tenant B got HTTP 200 for PUT /things/1/raw on tenant A's thing (expected 403 or 404)"
    ]
