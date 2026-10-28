import sqlalchemy
from sqlalchemy import text


def export(session):
    # ruleid: tik-raw-sql-without-tenant-predicate
    return session.execute(text("SELECT id, body FROM notes ORDER BY id")).all()


def purge(session):
    # ruleid: tik-raw-sql-without-tenant-predicate
    session.execute(sqlalchemy.text("delete from notes where id = :id"), {"id": 1})


def multiline(session):
    # ruleid: tik-raw-sql-without-tenant-predicate
    stmt = text(
        """
        UPDATE invoices
           SET paid = 1
         WHERE number = :number
        """
    )
    return stmt


def driver(conn):
    # ruleid: tik-raw-sql-without-tenant-predicate
    conn.exec_driver_sql("WITH x AS (SELECT * FROM notes) SELECT count(*) FROM x")


def scoped(session, principal):
    # ok: tik-raw-sql-without-tenant-predicate
    return session.execute(
        text("SELECT id, body FROM notes WHERE tenant_id = :tenant_id"),
        {"tenant_id": principal.tenant_id},
    ).all()


def no_table(session):
    # ok: tik-raw-sql-without-tenant-predicate
    return session.execute(text("SELECT 1")).scalar()


def ddl(session):
    # ok: tik-raw-sql-without-tenant-predicate
    session.execute(text("CREATE INDEX ix_notes_tenant ON notes (tenant_id)"))
