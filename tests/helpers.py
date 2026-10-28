"""Shared test helpers: resource descriptions and authenticated client pairs."""

from __future__ import annotations

from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tenant_isolation_kit import Resource, Tenant, TenantPair
from tenant_isolation_kit.matrix import HTTPClient

NOTES = Resource(
    name="note",
    collection="/notes",
    create=lambda canary: {"body": canary},
    tenant_field="tenant_id",
)
INVOICES = Resource(
    name="invoice",
    collection="/invoices",
    create=lambda canary: {"number": canary, "memo": canary},
    path_params={"number": "number"},
    tenant_header="X-Tenant-ID",
)


def clients(app: FastAPI) -> tuple[TestClient, TestClient]:
    """Two clients of ``app``: alice of tenant ``acme`` and bob of tenant ``globex``."""
    alice = TestClient(app, headers={"Authorization": "Bearer demo-token-alice"})
    bob = TestClient(app, headers={"Authorization": "Bearer demo-token-bob"})
    return alice, bob


def pair_for(app: FastAPI) -> TenantPair:
    alice, bob = clients(app)
    return TenantPair(
        a=Tenant("acme", cast(HTTPClient, alice)), b=Tenant("globex", cast(HTTPClient, bob))
    )
