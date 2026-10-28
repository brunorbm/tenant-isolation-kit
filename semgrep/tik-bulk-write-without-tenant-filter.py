import sqlalchemy
from sqlalchemy import delete, update


def delete_note(session, note_id):
    # ruleid: tik-bulk-write-without-tenant-filter
    session.execute(delete(Note).where(Note.id == note_id))


def mark_paid(session, ids):
    # ruleid: tik-bulk-write-without-tenant-filter
    session.execute(update(Invoice).where(Invoice.id.in_(ids)).values(paid=True))


def wipe(session):
    # ruleid: tik-bulk-write-without-tenant-filter
    session.execute(sqlalchemy.delete(Note))


def legacy(session, ids):
    # ruleid: tik-bulk-write-without-tenant-filter
    session.query(Invoice).filter(Invoice.id.in_(ids)).update({"paid": True})
    # ruleid: tik-bulk-write-without-tenant-filter
    session.query(Note).delete()


def scoped(session, principal, note_id):
    # ok: tik-bulk-write-without-tenant-filter
    session.execute(delete(Note).where(Note.id == note_id, Note.tenant_id == principal.tenant_id))


def scoped_chain(session, principal, ids):
    # ok: tik-bulk-write-without-tenant-filter
    session.execute(
        update(Invoice)
        .where(Invoice.id.in_(ids))
        .where(Invoice.tenant_id == principal.tenant_id)
        .values(paid=True)
    )


def scoped_legacy(session, principal, ids):
    # ok: tik-bulk-write-without-tenant-filter
    session.query(Invoice).filter(Invoice.tenant_id == principal.tenant_id).update({"paid": True})


def dict_update(settings, other):
    # ok: tik-bulk-write-without-tenant-filter
    settings.update(other)


def table_object(session, ids):
    # Known false negative, caught by the runtime guard instead.
    # ok: tik-bulk-write-without-tenant-filter
    session.execute(Invoice.__table__.update().where(Invoice.__table__.c.id.in_(ids)))
