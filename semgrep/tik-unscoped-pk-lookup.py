from sqlalchemy import select


def get_note(session, note_id):
    # ruleid: tik-unscoped-pk-lookup
    return session.get(Note, note_id)


def get_note_db(db, note_id):
    # ruleid: tik-unscoped-pk-lookup
    return db.get(Note, note_id, with_for_update=True)


def select_note(session, note_id):
    # ruleid: tik-unscoped-pk-lookup
    return session.scalars(select(Note).where(Note.id == note_id)).first()


def select_note_filter_by(session, note_id):
    # ruleid: tik-unscoped-pk-lookup
    return session.scalars(select(Note).filter_by(id=note_id)).one()


def legacy_query(session, note_id):
    # ruleid: tik-unscoped-pk-lookup
    a = session.query(Note).get(note_id)
    # ruleid: tik-unscoped-pk-lookup
    b = session.query(Note).filter(Note.id == note_id).first()
    return a, b


def scoped_select(session, principal, note_id):
    # ok: tik-unscoped-pk-lookup
    return session.scalars(
        select(Note).where(Note.id == note_id, Note.tenant_id == principal.tenant_id)
    ).first()


def scoped_chain(session, principal, note_id):
    # ok: tik-unscoped-pk-lookup
    stmt = select(Note).where(Note.id == note_id).where(Note.tenant_id == principal.tenant_id)
    return session.scalars(stmt).first()


def scoped_filter_by(session, principal, note_id):
    # ok: tik-unscoped-pk-lookup
    return session.query(Note).filter_by(id=note_id, tenant_id=principal.tenant_id).first()


def checked_after_get(session, principal, note_id):
    # ok: tik-unscoped-pk-lookup
    note = session.get(Note, note_id)
    if note is None or note.tenant_id != principal.tenant_id:
        raise LookupError(note_id)
    return note


def not_a_session(cache, key):
    # ok: tik-unscoped-pk-lookup
    return cache.get(Key, key)


def lowercase_key(session, name):
    # ok: tik-unscoped-pk-lookup
    return session.get(name, 1)
