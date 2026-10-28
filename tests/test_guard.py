"""Runtime guard: what it rejects in strict mode and how it scopes in permissive mode."""

from __future__ import annotations

import logging
from collections.abc import Callable, Hashable, Iterator

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import (
    Column,
    Engine,
    ForeignKey,
    Integer,
    String,
    Table,
    create_engine,
    delete,
    insert,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    aliased,
    mapped_column,
    relationship,
    sessionmaker,
)

from tenant_isolation_kit import (
    BYPASS_INFO_KEY,
    BYPASS_OPTION,
    TENANT_INFO_KEY,
    CrossTenantQueryError,
    CrossTenantWriteError,
    MissingTenantContextError,
    TenantGuard,
    UnscopedQueryError,
    Violation,
    bypass_tenant_guard,
    tenant_scope,
)
from tenant_isolation_kit.guard import _short_sql


class Base(DeclarativeBase):
    pass


class Owned(Base):
    __abstract__ = True
    tenant_id: Mapped[str] = mapped_column(String(20), index=True)


class Project(Owned):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50))
    tasks: Mapped[list[Task]] = relationship(back_populates="project", order_by="Task.id")


class Task(Owned):
    __tablename__ = "tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    title: Mapped[str] = mapped_column(String(50))
    project: Mapped[Project] = relationship(back_populates="tasks")


class Account(Base):
    """Tenant column with a different attribute name."""

    __tablename__ = "accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    org: Mapped[str] = mapped_column("tenant_id", String(20))


class Country(Base):
    """Shared reference data: not tenant-scoped."""

    __tablename__ = "countries"
    code: Mapped[str] = mapped_column(String(2), primary_key=True)


audit = Table(
    "audit_log",
    Base.metadata,
    Column("id", Integer, primary_key=True),
    Column("tenant_id", String(20)),
    Column("message", String(50)),
)

SCOPED: list[type[object] | Table] = [Owned, Account, audit]


def seed(session: Session) -> None:
    session.add_all(
        [
            Project(id=1, tenant_id="t1", name="alpha"),
            Project(id=2, tenant_id="t2", name="beta"),
            Project(id=3, tenant_id="t1", name="gamma"),
            Task(id=1, tenant_id="t1", project_id=1, title="t1 task"),
            # A corrupt row: tenant t2's task hangs off tenant t1's project.
            Task(id=2, tenant_id="t2", project_id=1, title="t2 task"),
            Account(id=1, org="t1"),
            Account(id=2, org="t2"),
            Country(code="FR"),
        ]
    )
    session.flush()
    session.execute(
        insert(audit), [{"tenant_id": "t1", "message": "a"}, {"tenant_id": "t2", "message": "b"}]
    )
    session.commit()


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        seed(session)
    yield engine
    engine.dispose()


OpenSession = Callable[..., Session]


@pytest.fixture
def violations() -> list[Violation]:
    return []


@pytest.fixture
def open_session(engine: Engine, violations: list[Violation]) -> Iterator[OpenSession]:
    opened: list[Session] = []

    def open_(tenant: Hashable | None = "t1", *, strict: bool = True) -> Session:
        info = {} if tenant is None else {TENANT_INFO_KEY: tenant}
        session = Session(engine, info=info)
        TenantGuard(SCOPED, strict=strict, on_violation=violations.append).install(session)
        opened.append(session)
        return session

    yield open_
    for session in opened:
        session.close()


# -- strict mode ---------------------------------------------------------------


def test_strict_accepts_explicit_predicate_for_bound_tenant(open_session: OpenSession) -> None:
    session = open_session("t1")
    rows = session.scalars(select(Project).where(Project.tenant_id == "t1").order_by(Project.id))
    assert [p.name for p in rows] == ["alpha", "gamma"]


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: select(Project), id="no-where"),
        pytest.param(lambda: select(Project).where(Project.id == 2), id="id-only"),
        pytest.param(
            lambda: select(Project).where(or_(Project.tenant_id == "t1", Project.id == 2)),
            id="or-branch",
        ),
        pytest.param(
            lambda: select(Project).join(Task).where(Project.tenant_id == Task.tenant_id),
            id="join-condition-only",
        ),
        pytest.param(
            lambda: select(Project, Task).join(Task).where(Project.tenant_id == "t1"),
            id="second-table",
        ),
        pytest.param(lambda: update(Project).where(Project.id == 2).values(name="x"), id="update"),
        pytest.param(lambda: delete(Project).where(Project.id == 2), id="delete"),
        pytest.param(lambda: select(audit), id="core-table"),
        pytest.param(lambda: select(Account), id="renamed-attribute"),
    ],
)
def test_strict_rejects_statements_without_tenant_predicate(
    open_session: OpenSession, build: Callable[[], object]
) -> None:
    session = open_session("t1")
    with pytest.raises(UnscopedQueryError, match="no explicit tenant_id predicate"):
        session.execute(build())  # type: ignore[call-overload]


def test_strict_rejects_session_get(open_session: OpenSession) -> None:
    with pytest.raises(UnscopedQueryError):
        open_session("t1").get(Project, 2)


@pytest.mark.parametrize(
    "where",
    [
        pytest.param(lambda: Project.tenant_id == "t2", id="eq"),
        pytest.param(lambda: "t2" == Project.tenant_id, id="eq-reversed"),  # noqa: SIM300
        pytest.param(lambda: Project.tenant_id.in_(["t1", "t2"]), id="in"),
    ],
)
def test_strict_rejects_predicate_for_another_tenant(
    open_session: OpenSession, where: Callable[[], object]
) -> None:
    with pytest.raises(CrossTenantQueryError, match="bound to tenant 't1'"):
        open_session("t1").execute(select(Project).where(where()))  # type: ignore[arg-type]


def test_strict_accepts_in_with_own_tenant_and_aliases(open_session: OpenSession) -> None:
    session = open_session("t1")
    alias = aliased(Project)
    rows = session.scalars(select(alias).where(alias.tenant_id.in_(["t1"]), alias.id == 1))
    assert [p.name for p in rows] == ["alpha"]


def test_strict_relationship_loads_are_scoped_not_rejected(open_session: OpenSession) -> None:
    session = open_session("t1")
    project = session.scalars(
        select(Project).where(Project.tenant_id == "t1", Project.id == 1)
    ).one()
    assert [t.title for t in project.tasks] == ["t1 task"]


def test_strict_expired_attribute_refresh_is_allowed(open_session: OpenSession) -> None:
    session = open_session("t1")
    project = session.scalars(
        select(Project).where(Project.tenant_id == "t1", Project.id == 1)
    ).one()
    session.expire(project, ["name"])
    assert project.name == "alpha"


def test_unscoped_tables_are_ignored(open_session: OpenSession) -> None:
    assert open_session(None).scalars(select(Country.code)).all() == ["FR"]


# -- permissive mode -------------------------------------------------------------


def test_permissive_scopes_select_and_reports(
    open_session: OpenSession, violations: list[Violation]
) -> None:
    session = open_session("t1", strict=False)
    assert sorted(p.name for p in session.scalars(select(Project))) == ["alpha", "gamma"]
    assert session.get(Project, 2) is None
    assert [v.kind for v in violations] == ["unscoped", "unscoped"]
    assert violations[0].tables == ("projects",)
    assert violations[0].corrected


def test_permissive_scopes_joins_aliases_and_renamed_columns(open_session: OpenSession) -> None:
    session = open_session("t1", strict=False)
    alias = aliased(Task)
    pairs = session.execute(
        select(Project.name, alias.title).join(alias, alias.project_id == Project.id)
    ).all()
    assert [tuple(p) for p in pairs] == [("alpha", "t1 task")]
    assert [a.id for a in session.scalars(select(Account))] == [1]


def test_permissive_cross_tenant_predicate_yields_nothing(
    open_session: OpenSession, violations: list[Violation]
) -> None:
    session = open_session("t1", strict=False)
    assert session.scalars(select(Project).where(Project.tenant_id == "t2")).all() == []
    assert violations[0].kind == "cross_tenant"


def test_permissive_scopes_bulk_update_and_delete(
    open_session: OpenSession, engine: Engine
) -> None:
    session = open_session("t1", strict=False)
    session.execute(update(Project).values(name="renamed"))
    session.execute(delete(Task).where(Task.id == 2))
    session.commit()
    with Session(engine) as raw:
        assert raw.scalars(select(Project.name).order_by(Project.id)).all() == [
            "renamed",
            "beta",
            "renamed",
        ]
        assert raw.get(Task, 2) is not None


def test_permissive_scopes_orm_bulk_update_by_primary_key(
    open_session: OpenSession, engine: Engine
) -> None:
    session = open_session("t1", strict=False)
    session.execute(update(Project), [{"id": 1, "name": "mine"}, {"id": 2, "name": "stolen"}])
    session.commit()
    with Session(engine) as raw:
        assert raw.scalars(select(Project.name).order_by(Project.id)).all() == [
            "mine",
            "beta",
            "gamma",
        ]


def test_permissive_cannot_correct_core_table_select(
    open_session: OpenSession, violations: list[Violation]
) -> None:
    rows = open_session("t1", strict=False).execute(select(audit.c.message)).all()
    assert len(rows) == 2  # documented limitation: reported, not corrected
    assert violations[0].corrected is False


def test_default_on_violation_logs_a_warning(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    session = Session(engine, info={TENANT_INFO_KEY: "t1"})
    TenantGuard([Owned], strict=False).install(session)
    with caplog.at_level(logging.WARNING, logger="tenant_isolation_kit"):
        session.scalars(select(Project)).all()
    assert "tenant isolation violation" in caplog.text
    session.close()


# -- text() ------------------------------------------------------------------------


def test_text_without_tenant_column_is_rejected(open_session: OpenSession) -> None:
    with pytest.raises(UnscopedQueryError, match=r"text\(\) SQL mentions projects"):
        open_session("t1").execute(text("SELECT name FROM projects"))


def test_text_binding_another_tenant_is_rejected(open_session: OpenSession) -> None:
    session = open_session("t1")
    sql = text("SELECT name FROM projects WHERE tenant_id = :tenant_id")
    assert session.execute(sql, {"tenant_id": "t1"}).scalars().all() == ["alpha", "gamma"]
    with pytest.raises(CrossTenantQueryError):
        session.execute(sql, {"tenant_id": "t2"})


def test_text_on_other_tables_is_ignored(open_session: OpenSession) -> None:
    session = open_session("t1")
    assert session.execute(text("SELECT 1")).scalar() == 1
    assert session.execute(text("SELECT count(*) FROM countries")).scalar() == 1


def test_permissive_text_is_reported_but_not_corrected(
    open_session: OpenSession, violations: list[Violation]
) -> None:
    rows = open_session("t1", strict=False).execute(text("SELECT name FROM projects")).all()
    assert len(rows) == 3
    assert violations[0].corrected is False


# -- writes ------------------------------------------------------------------------


@pytest.mark.parametrize("strict", [True, False])
def test_flush_rejects_rows_for_another_tenant(open_session: OpenSession, strict: bool) -> None:
    session = open_session("t1", strict=strict)
    session.add(Project(id=10, tenant_id="t2", name="planted"))
    with pytest.raises(CrossTenantWriteError, match="'t2'"):
        session.flush()


def test_flush_rejects_moving_a_row_to_another_tenant(open_session: OpenSession) -> None:
    session = open_session("t1")
    project = session.scalars(
        select(Project).where(Project.tenant_id == "t1", Project.id == 1)
    ).one()
    project.tenant_id = "t2"
    with pytest.raises(CrossTenantWriteError):
        session.flush()


def test_flush_fills_in_missing_tenant(open_session: OpenSession) -> None:
    session = open_session("t1")
    project, account = Project(id=10, name="new"), Account(id=10)
    session.add_all([project, account, Country(code="DE")])
    session.flush()
    assert (project.tenant_id, account.org) == ("t1", "t1")


@pytest.mark.parametrize("strict", [True, False])
def test_bulk_insert_rejects_another_tenant(open_session: OpenSession, strict: bool) -> None:
    session = open_session("t1", strict=strict)
    session.execute(insert(Project), [{"id": 10, "tenant_id": "t1", "name": "ok"}])
    with pytest.raises(CrossTenantWriteError, match="insert into projects"):
        session.execute(insert(Project), [{"id": 11, "tenant_id": "t2", "name": "planted"}])


@pytest.mark.parametrize(
    "values",
    [
        pytest.param({"id": 11, "tenant_id": "t2", "name": "planted"}, id="values"),
        pytest.param(
            [
                {"id": 11, "tenant_id": "t1", "name": "a"},
                {"id": 12, "tenant_id": "t2", "name": "b"},
            ],
            id="multi",
        ),
    ],
)
def test_insert_values_reject_another_tenant(open_session: OpenSession, values: object) -> None:
    session = open_session("t1", strict=False)
    with pytest.raises(CrossTenantWriteError):
        session.execute(insert(Project).values(values))  # type: ignore[arg-type]
    session.execute(insert(Project).values(id=13, tenant_id="t1", name="ok"))


# -- tenant binding, bypass, installation -------------------------------------------


def test_missing_tenant_fails_closed(open_session: OpenSession) -> None:
    session = open_session(None)
    with pytest.raises(MissingTenantContextError, match="projects"):
        session.execute(select(Project))
    with pytest.raises(MissingTenantContextError, match=r"text\(\)"):
        session.execute(text("SELECT * FROM projects"))
    session.add(Project(id=10, name="orphan"))
    with pytest.raises(MissingTenantContextError, match="flushing 1"):
        session.flush()


def test_tenant_scope_binds_through_a_context_variable(open_session: OpenSession) -> None:
    session = open_session(None)
    with tenant_scope("t2"):
        assert session.scalars(select(Project.name).where(Project.tenant_id == "t2")).all() == [
            "beta"
        ]
    with pytest.raises(ValueError, match="needs a tenant id"), tenant_scope(None):
        pass


def test_session_binding_wins_over_context(open_session: OpenSession) -> None:
    session = open_session("t1")
    with tenant_scope("t2"), pytest.raises(CrossTenantQueryError):
        session.execute(select(Project).where(Project.tenant_id == "t2"))


def test_bypass_context_manager(open_session: OpenSession) -> None:
    session = open_session("t1")
    with bypass_tenant_guard("test: count every tenant"):
        assert len(session.scalars(select(Project)).all()) == 3
        session.add(Project(id=10, tenant_id="t2", name="admin write"))
        session.flush()
    with pytest.raises(ValueError, match="non-empty reason"), bypass_tenant_guard("  "):
        pass


def test_bypass_by_session_info_and_execution_option(open_session: OpenSession) -> None:
    session = open_session("t1")
    assert (
        len(session.scalars(select(Project).execution_options(**{BYPASS_OPTION: True})).all()) == 3
    )
    session.info[BYPASS_INFO_KEY] = True
    assert len(session.scalars(select(Project)).all()) == 3


def test_custom_tenant_resolver(engine: Engine) -> None:
    session = Session(engine)
    TenantGuard([Owned], tenant_resolver=lambda s: "t2").install(session)
    assert session.scalars(select(Project.name).where(Project.tenant_id == "t2")).all() == ["beta"]
    session.close()


@pytest.mark.parametrize("target", ["sessionmaker", "class"])
def test_install_and_uninstall(engine: Engine, target: str) -> None:
    guard = TenantGuard([Owned])
    factory = sessionmaker(engine)

    class GuardedSession(Session):
        pass

    where: sessionmaker[Session] | type[Session] = (
        factory if target == "sessionmaker" else GuardedSession
    )
    assert guard.install(where) is guard
    with (
        factory() if target == "sessionmaker" else GuardedSession(engine) as session,
        pytest.raises(MissingTenantContextError),
    ):
        session.execute(select(Project))
    guard.uninstall(where)
    with factory() if target == "sessionmaker" else GuardedSession(engine) as session:
        assert len(session.scalars(select(Project)).all()) == 3


def test_models_declared_after_the_guard_are_covered(open_session: OpenSession) -> None:
    session = open_session("t1")

    class Late(Owned):
        __tablename__ = "late_rows"
        id: Mapped[int] = mapped_column(primary_key=True)

    with pytest.raises(UnscopedQueryError, match="late_rows"):
        session.execute(select(Late))


def test_configuration_errors() -> None:
    with pytest.raises(ValueError, match="at least one"):
        TenantGuard([])
    with pytest.raises(TypeError, match="Country is registered"):
        TenantGuard([Country]).tenant_tables()
    bare = Table("bare", Base.metadata, Column("id", Integer, primary_key=True))
    with pytest.raises(TypeError, match="table 'bare' has no 'tenant_id'"):
        TenantGuard([bare]).tenant_tables()
    Base.metadata.remove(bare)


def test_short_sql_truncates_and_survives_compile_errors() -> None:
    long = select(Project).where(*(Project.name == str(i) for i in range(60)))
    assert _short_sql(long).endswith("...")

    class Broken(Table):
        def __str__(self) -> str:
            raise RuntimeError("cannot compile")

    assert _short_sql(Broken("broken", Base.metadata)) == "Broken"
    Base.metadata.remove(Base.metadata.tables["broken"])


# -- property: permissive mode never returns or modifies another tenant's rows ------

TENANTS = ("t1", "t2", "t3")


@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    owners=st.lists(st.sampled_from(TENANTS), max_size=12),
    bound=st.sampled_from(TENANTS),
    forged=st.sampled_from(TENANTS),
)
def test_property_permissive_guard_confines_reads_and_writes(
    owners: list[str], bound: str, forged: str
) -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as raw:
        raw.add_all(Project(id=i, tenant_id=t, name="orig") for i, t in enumerate(owners, 1))
        raw.commit()
    session = Session(engine, info={TENANT_INFO_KEY: bound})
    TenantGuard(SCOPED, strict=False, on_violation=lambda v: None).install(session)

    mine = {i for i, t in enumerate(owners, 1) if t == bound}
    assert {p.id for p in session.scalars(select(Project))} == mine
    assert {
        p.id for p in session.scalars(select(Project).where(Project.tenant_id == forged))
    } <= mine
    session.execute(update(Project).values(name="changed"))
    session.execute(delete(Project).where(Project.tenant_id == forged))
    session.commit()
    session.close()

    with Session(engine) as raw:
        for project in raw.scalars(select(Project)):
            assert (project.tenant_id == bound) == (project.name == "changed")
        survivors = {p.id for p in raw.scalars(select(Project))}
        others = {i for i, t in enumerate(owners, 1) if t != bound}
        assert others <= survivors
    engine.dispose()
