from fastapi import APIRouter, FastAPI
from sqlalchemy import delete, select

app = FastAPI()
router = APIRouter()


@app.get("/notes/{note_id}")
def get_note(note_id: int, session: Session):
    # ruleid: tik-path-param-lookup-without-ownership-check
    note = session.get(Note, note_id)
    return note


@router.delete("/notes/{note_id}")
def delete_note(note_id: int, session: Session):
    # ruleid: tik-path-param-lookup-without-ownership-check
    session.execute(delete(Note).where(Note.id == note_id))
    session.commit()


@router.patch("/projects/{project_uuid}/notes")
def touch(project_uuid: str, db: Session):
    # ruleid: tik-path-param-lookup-without-ownership-check
    return db.scalars(select(Note).where(Note.project_uuid == project_uuid)).all()


@app.get("/notes/{note_id}")
def get_note_scoped(note_id: int, principal: Principal, session: Session):
    # ok: tik-path-param-lookup-without-ownership-check
    return session.scalars(
        select(Note).where(Note.id == note_id, Note.tenant_id == principal.tenant_id)
    ).first()


@app.get("/notes/{note_id}")
def get_note_checked(note_id: int, principal: Principal, session: Session):
    # ok: tik-path-param-lookup-without-ownership-check
    note = session.get(Note, note_id)
    if note is None or note.tenant_id != principal.tenant_id:
        raise NotFound()
    return note


@app.get("/notes/{note_id}")
def get_note_via_helper(note_id: int, principal: Principal, session: Session):
    # ok: tik-path-param-lookup-without-ownership-check
    return own_note(session, principal, note_id)


@app.get("/notes")
def search(owner_id: int, session: Session):
    # ok: tik-path-param-lookup-without-ownership-check
    return session.scalars(select(Note).where(Note.owner_id == owner_id)).all()


def not_a_route(note_id: int, session: Session):
    # ok: tik-path-param-lookup-without-ownership-check
    return session.get(Note, note_id)


def create_app(app, principal):
    # Handlers nested in an app factory: a tenant check in a sibling handler must
    # not hide the missing check in this one.
    @app.get("/scoped/{item_id}")
    def scoped(item_id: int, session):
        return session.scalars(select(Item).where(Item.id == item_id, Item.tenant_id == principal.tenant_id))

    @app.get("/items/{item_id}")
    def unscoped(item_id: int, session):
        # ruleid: tik-path-param-lookup-without-ownership-check
        return session.get(Item, item_id)

    return app
