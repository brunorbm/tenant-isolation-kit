"""Shared plumbing for the two example apps: models, demo authentication, sessions.

Everything here is deliberately correct. The seeded bugs live only in the route
handlers of ``vulnerable_app/main.py``, so that diffing it against
``fixed_app/main.py`` shows exactly what each fix is.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import Engine, ForeignKey, String, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from tenant_isolation_kit import TENANT_INFO_KEY, TenantGuard


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)


class TenantScoped(Base):
    """Abstract base: every subclass is a tenant-owned table."""

    __abstract__ = True

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)


class Note(TenantScoped):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    body: Mapped[str] = mapped_column(String(500))


class Invoice(TenantScoped):
    __tablename__ = "invoices"
    __table_args__ = (UniqueConstraint("tenant_id", "number"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    number: Mapped[str] = mapped_column(String(64))
    memo: Mapped[str] = mapped_column(String(500))
    paid: Mapped[bool] = mapped_column(default=False)


@dataclass(frozen=True)
class Principal:
    user: str
    tenant_id: str


# Demo credentials only: a real app verifies a signed token or a session cookie.
DEMO_TOKENS = {
    "demo-token-alice": Principal(user="alice", tenant_id="acme"),
    "demo-token-bob": Principal(user="bob", tenant_id="globex"),
}


def make_engine() -> Engine:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all(Tenant(id=p.tenant_id) for p in DEMO_TOKENS.values())
        session.commit()
    return engine


def make_session_factory(engine: Engine, guard: TenantGuard | None = None) -> sessionmaker[Session]:
    factory = sessionmaker(engine, expire_on_commit=False)
    if guard is not None:
        guard.install(factory)
    return factory


def make_guard(*, strict: bool = True) -> TenantGuard:
    return TenantGuard([TenantScoped], strict=strict)


def get_principal(authorization: Annotated[str, Header()] = "") -> Principal:
    scheme, _, token = authorization.partition(" ")
    principal = DEMO_TOKENS.get(token) if scheme.lower() == "bearer" else None
    if principal is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def get_session(request: Request, principal: CurrentPrincipal) -> Iterator[Session]:
    """One session per request, bound to the caller's tenant for the runtime guard."""
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory(info={TENANT_INFO_KEY: principal.tenant_id}) as session:
        yield session


DbSession = Annotated[Session, Depends(get_session)]


def note_out(note: Note) -> dict[str, object]:
    return {"id": note.id, "body": note.body}


def invoice_out(invoice: Invoice) -> dict[str, object]:
    return {"id": invoice.id, "number": invoice.number, "memo": invoice.memo, "paid": invoice.paid}
