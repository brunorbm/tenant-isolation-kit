"""The same API as ``vulnerable_app`` with every seeded bug fixed.

It also runs under ``TenantGuard(strict=True)``: every statement on a tenant table
names the caller's tenant explicitly, so the guard has nothing to correct.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Body, FastAPI, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import Engine, delete, select, text, update

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


class InvoiceIn(BaseModel):
    number: str
    memo: str


# FIX V8: the cache key includes the tenant.
_receipt_cache: dict[tuple[str, int], str] = {}


def create_app(engine: Engine | None = None, guard: TenantGuard | None = None) -> FastAPI:
    app = FastAPI(title="fixed example")
    app.state.session_factory = make_session_factory(engine or make_engine(), guard)
    _receipt_cache.clear()

    @app.post("/notes", status_code=201)
    def create_note(
        payload: NoteIn, principal: CurrentPrincipal, session: DbSession
    ) -> dict[str, object]:
        # FIX V6: the owner always comes from the authenticated principal. The model
        # has no tenant_id field, so a forged one is ignored.
        note = Note(tenant_id=principal.tenant_id, body=payload.body)
        session.add(note)
        session.commit()
        return note_out(note)

    @app.get("/notes")
    def list_notes(principal: CurrentPrincipal, session: DbSession) -> list[dict[str, object]]:
        # FIX V5: no tenant selector in the request.
        notes = session.scalars(
            select(Note).where(Note.tenant_id == principal.tenant_id).order_by(Note.id)
        )
        return [note_out(n) for n in notes]

    @app.get("/notes/export")
    def export_notes(principal: CurrentPrincipal, session: DbSession) -> Response:
        # FIX V4: the raw SQL carries a bound tenant predicate.
        rows = session.execute(
            text("SELECT id, body FROM notes WHERE tenant_id = :tenant_id ORDER BY id"),
            {"tenant_id": principal.tenant_id},
        ).all()
        csv = "id,body\n" + "".join(f"{row.id},{row.body}\n" for row in rows)
        return Response(csv, media_type="text/csv")

    def own_note(session: DbSession, principal: CurrentPrincipal, note_id: int) -> Note:
        note = session.scalars(
            select(Note).where(Note.id == note_id, Note.tenant_id == principal.tenant_id)
        ).first()
        if note is None:
            raise HTTPException(status_code=404)
        return note

    @app.get("/notes/{note_id}")
    def get_note(
        note_id: int, principal: CurrentPrincipal, session: DbSession
    ) -> dict[str, object]:
        # FIX V1: lookup scoped to the caller's tenant; 404 (not 403) hides existence.
        return note_out(own_note(session, principal, note_id))

    @app.patch("/notes/{note_id}")
    def update_note(
        note_id: int, payload: NoteIn, principal: CurrentPrincipal, session: DbSession
    ) -> dict[str, object]:
        # FIX V2
        note = own_note(session, principal, note_id)
        note.body = payload.body
        session.commit()
        return note_out(note)

    @app.delete("/notes/{note_id}", status_code=204)
    def delete_note(note_id: int, principal: CurrentPrincipal, session: DbSession) -> Response:
        # FIX V3
        result = session.execute(
            delete(Note).where(Note.id == note_id, Note.tenant_id == principal.tenant_id)
        )
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
    def list_invoices(principal: CurrentPrincipal, session: DbSession) -> list[dict[str, object]]:
        # FIX V10: the X-Tenant-ID header is not read at all.
        invoices = session.scalars(select(Invoice).where(Invoice.tenant_id == principal.tenant_id))
        return [invoice_out(i) for i in invoices]

    @app.post("/invoices/mark-paid")
    def mark_paid(
        ids: Annotated[list[int], Body(embed=True)], principal: CurrentPrincipal, session: DbSession
    ) -> dict[str, int]:
        # FIX V7: bulk UPDATE through the mapped class, with the tenant predicate.
        result = session.execute(
            update(Invoice)
            .where(Invoice.id.in_(ids), Invoice.tenant_id == principal.tenant_id)
            .values(paid=True)
        )
        session.commit()
        return {"updated": result.rowcount}  # type: ignore[attr-defined]

    @app.get("/invoices/by-number/{number}")
    def get_invoice_by_number(
        number: str, principal: CurrentPrincipal, session: DbSession
    ) -> dict[str, object]:
        # FIX V9
        invoice = session.scalars(
            select(Invoice).where(
                Invoice.number == number, Invoice.tenant_id == principal.tenant_id
            )
        ).first()
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
        key = (principal.tenant_id, invoice_id)
        if key not in _receipt_cache:
            invoice = session.scalars(
                select(Invoice).where(
                    Invoice.id == invoice_id, Invoice.tenant_id == principal.tenant_id
                )
            ).first()
            if invoice is None:
                raise HTTPException(status_code=404)
            _receipt_cache[key] = f"Receipt {invoice.number}: {invoice.memo}"
        return Response(_receipt_cache[key], media_type="text/plain")

    return app


app = create_app()
