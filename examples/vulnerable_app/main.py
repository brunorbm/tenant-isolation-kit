"""A small notes-and-invoices API with ten seeded cross-tenant bugs (V1-V10).

DO NOT USE AS A TEMPLATE. Each bug is marked ``SEEDED BUG Vn``; the catalog in
``examples/seeded_bugs.py`` says which layer of tenant-isolation-kit catches it.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Body, FastAPI, Header, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import Engine, delete, select, text

from examples.common import (
    CurrentPrincipal,
    DbSession,
    Invoice,
    Note,
    invoice_out,
    make_engine,
    make_session_factory,
    note_out,
)
from tenant_isolation_kit import TenantGuard


class NoteIn(BaseModel):
    body: str
    tenant_id: str | None = None


class InvoiceIn(BaseModel):
    number: str
    memo: str


# SEEDED BUG V8: the cache key is the invoice id alone, not (tenant, id).
_receipt_cache: dict[int, str] = {}


def create_app(engine: Engine | None = None, guard: TenantGuard | None = None) -> FastAPI:
    app = FastAPI(title="vulnerable example")
    app.state.session_factory = make_session_factory(engine or make_engine(), guard)
    _receipt_cache.clear()

    @app.post("/notes", status_code=201)
    def create_note(
        payload: NoteIn, principal: CurrentPrincipal, session: DbSession
    ) -> dict[str, object]:
        # SEEDED BUG V6: the owner is taken from the request body when present.
        note = Note(tenant_id=payload.tenant_id or principal.tenant_id, body=payload.body)
        session.add(note)
        session.commit()
        return note_out(note)

    @app.get("/notes")
    def list_notes(
        principal: CurrentPrincipal,
        session: DbSession,
        tenant_id: Annotated[str | None, Query()] = None,
    ) -> list[dict[str, object]]:
        # SEEDED BUG V5: an optional query parameter overrides the caller's tenant.
        owner = tenant_id or principal.tenant_id
        notes = session.scalars(select(Note).where(Note.tenant_id == owner).order_by(Note.id))
        return [note_out(n) for n in notes]

    @app.get("/notes/export")
    def export_notes(principal: CurrentPrincipal, session: DbSession) -> Response:
        # SEEDED BUG V4: raw SQL with no tenant predicate exports every tenant's notes.
        rows = session.execute(text("SELECT id, body FROM notes ORDER BY id")).all()
        csv = "id,body\n" + "".join(f"{row.id},{row.body}\n" for row in rows)
        return Response(csv, media_type="text/csv")

    @app.get("/notes/{note_id}")
    def get_note(note_id: int, session: DbSession) -> dict[str, object]:
        # SEEDED BUG V1: primary-key lookup with no ownership check.
        note = session.get(Note, note_id)
        if note is None:
            raise HTTPException(status_code=404)
        return note_out(note)

    @app.patch("/notes/{note_id}")
    def update_note(note_id: int, payload: NoteIn, session: DbSession) -> dict[str, object]:
        # SEEDED BUG V2: select by id only.
        note = session.scalars(select(Note).where(Note.id == note_id)).first()
        if note is None:
            raise HTTPException(status_code=404)
        note.body = payload.body
        session.commit()
        return note_out(note)

    @app.delete("/notes/{note_id}", status_code=204)
    def delete_note(note_id: int, session: DbSession) -> Response:
        # SEEDED BUG V3: Core DELETE filtered by id only.
        result = session.execute(delete(Note).where(Note.id == note_id))
        session.commit()
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise HTTPException(status_code=404)
        return Response(status_code=204)

    @app.post("/invoices", status_code=201)
    def create_invoice(
        payload: InvoiceIn, principal: CurrentPrincipal, session: DbSession
    ) -> dict[str, object]:
        invoice = Invoice(tenant_id=principal.tenant_id, number=payload.number, memo=payload.memo)
        session.add(invoice)
        session.commit()
        return invoice_out(invoice)

    @app.get("/invoices")
    def list_invoices(
        principal: CurrentPrincipal,
        session: DbSession,
        x_tenant_id: Annotated[str | None, Header()] = None,
    ) -> list[dict[str, object]]:
        # SEEDED BUG V10: a client-supplied X-Tenant-ID header picks the tenant.
        owner = x_tenant_id or principal.tenant_id
        invoices = session.scalars(select(Invoice).where(Invoice.tenant_id == owner))
        return [invoice_out(i) for i in invoices]

    @app.post("/invoices/mark-paid")
    def mark_paid(
        ids: Annotated[list[int], Body(embed=True)], session: DbSession
    ) -> dict[str, int]:
        # SEEDED BUG V7: bulk Core UPDATE on the table object, filtered by id only.
        table = Invoice.metadata.tables["invoices"]
        result = session.execute(table.update().where(table.c.id.in_(ids)).values(paid=True))
        session.commit()
        return {"updated": result.rowcount}  # type: ignore[attr-defined]

    @app.get("/invoices/by-number/{number}")
    def get_invoice_by_number(number: str, session: DbSession) -> dict[str, object]:
        # SEEDED BUG V9: lookup by a business key, which is unique only per tenant.
        invoice = session.scalars(select(Invoice).where(Invoice.number == number)).first()
        if invoice is None:
            raise HTTPException(status_code=404)
        return invoice_out(invoice)

    @app.get("/invoices/{invoice_id}")
    def get_invoice(
        invoice_id: int, principal: CurrentPrincipal, session: DbSession
    ) -> dict[str, object]:
        invoice = session.scalars(
            select(Invoice).where(
                Invoice.id == invoice_id, Invoice.tenant_id == principal.tenant_id
            )
        ).first()
        if invoice is None:
            raise HTTPException(status_code=404)
        return invoice_out(invoice)

    @app.get("/invoices/{invoice_id}/receipt")
    def get_receipt(invoice_id: int, principal: CurrentPrincipal, session: DbSession) -> Response:
        if invoice_id not in _receipt_cache:
            invoice = session.scalars(
                select(Invoice).where(
                    Invoice.id == invoice_id, Invoice.tenant_id == principal.tenant_id
                )
            ).first()
            if invoice is None:
                raise HTTPException(status_code=404)
            _receipt_cache[invoice_id] = f"Receipt {invoice.number}: {invoice.memo}"
        return Response(_receipt_cache[invoice_id], media_type="text/plain")

    return app


app = create_app()
