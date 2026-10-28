"""Catalog of the bugs seeded in ``vulnerable_app`` and the layer expected to catch each.

The tests in ``tests/test_seeded_bugs.py`` and ``tests/test_semgrep_rules.py`` assert
every claim in this table, in both directions: a layer marked as catching a bug must
catch it, and a layer marked as missing it must miss it (so the table cannot silently
go stale). ``scripts/render_bug_table.py`` renders it into the README.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SeededBug:
    id: str
    route: str
    handler: str
    summary: str
    cwe: str
    #: Semgrep rule ids expected to fire inside the handler (empty: semgrep misses it).
    semgrep: tuple[str, ...]
    #: Case ids of the cross-tenant matrix expected to report it (empty: missed).
    matrix: tuple[str, ...]
    #: Whether ``TenantGuard(strict=True)`` raises when the bug is exploited.
    guard: bool


SEEDED_BUGS: tuple[SeededBug, ...] = (
    SeededBug(
        "V1",
        "GET /notes/{note_id}",
        "get_note",
        "`session.get(Note, id)` with no ownership check",
        "CWE-639",
        ("tik-unscoped-pk-lookup", "tik-path-param-lookup-without-ownership-check"),
        ("note:read:GET /notes/{note_id}",),
        True,
    ),
    SeededBug(
        "V2",
        "PATCH /notes/{note_id}",
        "update_note",
        "`select(Note).where(Note.id == id)` then update",
        "CWE-639",
        ("tik-unscoped-pk-lookup", "tik-path-param-lookup-without-ownership-check"),
        ("note:write:PATCH /notes/{note_id}",),
        True,
    ),
    SeededBug(
        "V3",
        "DELETE /notes/{note_id}",
        "delete_note",
        "Core `delete(Note).where(Note.id == id)`",
        "CWE-639",
        ("tik-bulk-write-without-tenant-filter", "tik-path-param-lookup-without-ownership-check"),
        ("note:write:DELETE /notes/{note_id}",),
        True,
    ),
    SeededBug(
        "V4",
        "GET /notes/export",
        "export_notes",
        "raw `text()` SQL with no tenant predicate",
        "CWE-284",
        ("tik-raw-sql-without-tenant-predicate",),
        ("note:list:GET /notes/export", "note:forge-query:GET /notes/export"),
        True,
    ),
    SeededBug(
        "V5",
        "GET /notes?tenant_id=",
        "list_notes",
        "tenant chosen by a query parameter",
        "CWE-639",
        ("tik-tenant-id-from-request",),
        ("note:forge-query:GET /notes",),
        True,
    ),
    SeededBug(
        "V6",
        "POST /notes",
        "create_note",
        "owner taken from the request body",
        "CWE-639",
        ("tik-tenant-id-from-request",),
        ("note:forge-body:POST /notes",),
        True,
    ),
    SeededBug(
        "V7",
        "POST /invoices/mark-paid",
        "mark_paid",
        "bulk `Invoice.__table__.update()` filtered by id only",
        "CWE-639",
        (),
        (),
        True,
    ),
    SeededBug(
        "V8",
        "GET /invoices/{invoice_id}/receipt",
        "get_receipt",
        "response cache keyed by invoice id, not (tenant, id)",
        "CWE-524",
        (),
        ("invoice:read:GET /invoices/{invoice_id}/receipt",),
        False,
    ),
    SeededBug(
        "V9",
        "GET /invoices/by-number/{number}",
        "get_invoice_by_number",
        "lookup by a per-tenant business key",
        "CWE-639",
        (),
        ("invoice:read:GET /invoices/by-number/{number}",),
        True,
    ),
    SeededBug(
        "V10",
        "GET /invoices (X-Tenant-ID)",
        "list_invoices",
        "tenant chosen by a client header",
        "CWE-639",
        ("tik-tenant-id-from-request",),
        ("invoice:forge-header:GET /invoices",),
        True,
    ),
)
