"""Every claim of ``examples/seeded_bugs.py`` about the matrix and the runtime guard.

Each seeded bug has an exploit below. The exploit returns True when the attacker
(bob, tenant ``globex``) reached data of the victim (alice, tenant ``acme``).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from examples.common import TenantScoped, make_guard
from examples.fixed_app.main import create_app as create_fixed_app
from examples.seeded_bugs import SEEDED_BUGS, SeededBug
from examples.vulnerable_app.main import create_app as create_vulnerable_app
from tenant_isolation_kit import (
    Case,
    CrossTenantWriteError,
    TenantGuard,
    TenantIsolationError,
    TenantPair,
    Violation,
    build_cases,
    discover_routes,
)
from tests.helpers import INVOICES, NOTES, clients, pair_for

BUGS = {bug.id: bug for bug in SEEDED_BUGS}


@dataclass
class World:
    alice: TestClient
    bob: TestClient
    canary: str
    note_id: int
    invoice_id: int


def make_world(app: FastAPI) -> World:
    alice, bob = clients(app)
    canary = f"acme-secret-{secrets.token_hex(4)}"
    note = alice.post("/notes", json={"body": canary})
    invoice = alice.post("/invoices", json={"number": canary, "memo": canary})
    assert note.status_code == invoice.status_code == 201
    return World(alice, bob, canary, note.json()["id"], invoice.json()["id"])


def _v1(w: World) -> bool:
    return w.canary in w.bob.get(f"/notes/{w.note_id}").text


def _v2(w: World) -> bool:
    w.bob.patch(f"/notes/{w.note_id}", json={"body": "defaced"})
    return "defaced" in w.alice.get("/notes").text


def _v3(w: World) -> bool:
    w.bob.delete(f"/notes/{w.note_id}")
    return w.canary not in w.alice.get("/notes").text


def _v4(w: World) -> bool:
    return w.canary in w.bob.get("/notes/export").text


def _v5(w: World) -> bool:
    return w.canary in w.bob.get("/notes", params={"tenant_id": "acme"}).text


def _v6(w: World) -> bool:
    w.bob.post("/notes", json={"body": "planted", "tenant_id": "acme"})
    return "planted" in w.alice.get("/notes").text


def _v7(w: World) -> bool:
    w.bob.post("/invoices/mark-paid", json={"ids": [w.invoice_id]})
    paid: bool = w.alice.get(f"/invoices/{w.invoice_id}").json()["paid"]
    return paid


def _v8(w: World) -> bool:
    receipt = f"/invoices/{w.invoice_id}/receipt"
    assert w.canary in w.alice.get(receipt).text
    return w.canary in w.bob.get(receipt).text


def _v9(w: World) -> bool:
    return w.canary in w.bob.get(f"/invoices/by-number/{w.canary}").text


def _v10(w: World) -> bool:
    return w.canary in w.bob.get("/invoices", headers={"X-Tenant-ID": "acme"}).text


EXPLOITS: dict[str, Callable[[World], bool]] = {
    "V1": _v1,
    "V2": _v2,
    "V3": _v3,
    "V4": _v4,
    "V5": _v5,
    "V6": _v6,
    "V7": _v7,
    "V8": _v8,
    "V9": _v9,
    "V10": _v10,
}
bug_params = [pytest.param(bug, id=bug.id) for bug in SEEDED_BUGS]


def test_every_seeded_bug_has_an_exploit() -> None:
    assert set(EXPLOITS) == set(BUGS)


@pytest.mark.parametrize("bug", bug_params)
def test_exploit_works_on_the_unguarded_vulnerable_app(bug: SeededBug) -> None:
    assert EXPLOITS[bug.id](make_world(create_vulnerable_app()))


@pytest.mark.parametrize("strict", [False, True], ids=["permissive", "strict"])
@pytest.mark.parametrize("guarded", [False, True], ids=["bare", "guarded"])
@pytest.mark.parametrize("bug", bug_params)
def test_exploit_fails_on_the_fixed_app(bug: SeededBug, guarded: bool, strict: bool) -> None:
    guard = make_guard(strict=strict) if guarded else None
    assert not EXPLOITS[bug.id](make_world(create_fixed_app(guard=guard)))


@pytest.mark.parametrize("bug", bug_params)
def test_strict_guard_catches_the_bugs_the_catalog_says_it_catches(bug: SeededBug) -> None:
    world = make_world(create_vulnerable_app(guard=make_guard(strict=True)))
    if bug.guard:
        with pytest.raises(TenantIsolationError):
            EXPLOITS[bug.id](world)
    else:
        assert EXPLOITS[bug.id](world)


# In permissive mode the guard rewrites what it can and reports it. It cannot rewrite
# text() SQL (V4) and never sees an application-level cache (V8); a forged owner on
# a write (V6) is rejected in both modes.
PERMISSIVE_LEAKS = {"V4", "V8"}
PERMISSIVE_RAISES = {"V6"}


@pytest.mark.parametrize("bug", bug_params)
def test_permissive_guard_contains_and_reports(bug: SeededBug) -> None:
    violations: list[Violation] = []
    guard = TenantGuard([TenantScoped], strict=False, on_violation=violations.append)
    world = make_world(create_vulnerable_app(guard=guard))
    assert violations == []  # the owner's own requests are clean
    if bug.id in PERMISSIVE_RAISES:
        with pytest.raises(CrossTenantWriteError):
            EXPLOITS[bug.id](world)
        return
    assert EXPLOITS[bug.id](world) is (bug.id in PERMISSIVE_LEAKS)
    assert bool(violations) is (bug.id != "V8")
    if bug.id == "V4":
        assert [v.corrected for v in violations] == [False]


def _run(case: Case, pair: TenantPair) -> bool:
    return bool(case.run(pair))


def test_matrix_reports_exactly_the_cataloged_cases() -> None:
    cases = build_cases([NOTES, INVOICES], discover_routes(create_vulnerable_app()))
    failing = {c.id for c in cases if _run(c, pair_for(create_vulnerable_app()))}
    assert failing == {case_id for bug in SEEDED_BUGS for case_id in bug.matrix}


@pytest.mark.tenant_matrix(app=create_fixed_app(), resources=[NOTES, INVOICES])
def test_fixed_app_passes_the_matrix_under_the_strict_guard(
    cross_tenant_case: Case, tenant_pair: TenantPair
) -> None:
    cross_tenant_case.check(tenant_pair)
