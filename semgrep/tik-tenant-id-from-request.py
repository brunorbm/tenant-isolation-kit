from typing import Annotated

from fastapi import Header, Query, Request
from sqlalchemy import select


def list_notes(principal, session, tenant_id: Annotated[str | None, Query()] = None):
    owner = tenant_id or principal.tenant_id
    # ruleid: tik-tenant-id-from-request
    return session.scalars(select(Note).where(Note.tenant_id == owner))


def list_invoices(principal, session, x_tenant_id: Annotated[str | None, Header()] = None):
    # ruleid: tik-tenant-id-from-request
    return session.scalars(select(Invoice).where(Invoice.tenant_id == (x_tenant_id or principal.tenant_id)))


def create_note(payload, principal, session):
    # ruleid: tik-tenant-id-from-request
    note = Note(tenant_id=payload.tenant_id or principal.tenant_id, body=payload.body)
    session.add(note)


async def import_notes(request: Request, session):
    data = await request.json()
    note = Note(body=data["body"])
    # ruleid: tik-tenant-id-from-request
    note.tenant_id = data["tenant"]
    session.add(note)


def by_header(request: Request, session):
    tenant = request.headers.get("x-tenant-id")
    # ruleid: tik-tenant-id-from-request
    return session.query(Note).filter_by(tenant_id=tenant).all()


def safe_list(principal, session):
    # ok: tik-tenant-id-from-request
    return session.scalars(select(Note).where(Note.tenant_id == principal.tenant_id))


def safe_create(payload, principal, session):
    # ok: tik-tenant-id-from-request
    note = Note(tenant_id=principal.tenant_id, body=payload.body)
    session.add(note)


def checked(principal, session, tenant_id: str):
    require_membership(principal, tenant_id)
    # ok: tik-tenant-id-from-request
    return session.scalars(select(Note).where(Note.tenant_id == tenant_id))


def unrelated(payload, session):
    # ok: tik-tenant-id-from-request
    return session.scalars(select(Note).where(Note.body == payload.body))
