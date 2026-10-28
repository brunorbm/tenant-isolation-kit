"""Runtime guard: scope every SQLAlchemy statement to the bound tenant.

The guard hooks two Session events:

``do_orm_execute``
    Every ``Session.execute()`` (and therefore ``Session.get()``, ``Query``, lazy and
    eager relationship loads, ORM and Core ``update()``/``delete()``, ``text()``).
    The guard finds the tenant-scoped tables the statement references, then

    1. fails closed with :class:`MissingTenantContextError` if no tenant is bound;
    2. checks that the statement *as written* carries an explicit tenant predicate
       (``<tenant column> = <value>`` or ``IN (...)`` at the top level of a WHERE
       clause) for each of them, and that the value is the bound tenant;
    3. rewrites the statement so that it is scoped anyway: ``with_loader_criteria``
       for ORM selects (it follows joins, aliases and relationship loads), an extra
       ``WHERE`` for ``update()``/``delete()``.

    Step 2 failures raise in strict mode. In permissive mode they are reported through
    ``on_violation`` and step 3 still scopes the statement, so a missing predicate
    degrades to "no rows" instead of "another tenant's rows".

``before_flush``
    Unit-of-work writes. New rows without a tenant get the bound tenant; a new or
    modified row whose tenant differs from the bound one raises
    :class:`CrossTenantWriteError` in both modes, because there is no safe automatic
    fix for a write aimed at another tenant.

The guard is a safety net, not the access-control model: see ``docs/design.md`` for
what it cannot see (connections used outside a Session, raw DB-API cursors, caches).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Hashable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias, cast

from sqlalchemy import Table, event, inspect
from sqlalchemy.orm import Mapper, ORMExecuteState, Session, sessionmaker, with_loader_criteria
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.elements import (
    BinaryExpression,
    BindParameter,
    BooleanClauseList,
    ClauseElement,
    ColumnClause,
    ColumnElement,
    Grouping,
    TextClause,
)
from sqlalchemy.sql.expression import Delete, Update
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.selectable import TableClause

from .context import BYPASS_OPTION, current_tenant, is_bypassed
from .errors import (
    CrossTenantQueryError,
    CrossTenantWriteError,
    MissingTenantContextError,
    TenantIsolationError,
    UnscopedQueryError,
)

__all__ = ["TenantGuard", "Violation"]

_log = logging.getLogger("tenant_isolation_kit")
_UNKNOWN = object()
_MAX_SQL_IN_MESSAGE = 400

ViolationKind: TypeAlias = Literal["unscoped", "cross_tenant"]
InstallTarget: TypeAlias = "Session | sessionmaker[Any] | type[Session]"


@dataclass(frozen=True)
class Violation:
    """A statement the guard had to correct. Passed to ``on_violation``."""

    kind: ViolationKind
    tables: tuple[str, ...]
    sql: str
    message: str
    #: False when the guard could not rewrite the statement (``text()``, Core selects
    #: on a ``Table``): in permissive mode such a statement runs unscoped.
    corrected: bool


@dataclass(frozen=True)
class _TenantTable:
    table: Table
    column: Column[Any]
    classes: tuple[type[Any], ...] = field(default=())


def _default_on_violation(violation: Violation) -> None:
    _log.warning("tenant isolation violation: %s", violation.message)


def _conjuncts(clause: ClauseElement | None) -> Iterator[ClauseElement]:
    """Yield the AND-ed terms of a WHERE clause. OR branches are not descended into:
    ``tenant_id = 1 OR true`` must not count as a tenant predicate."""
    if clause is None:
        return
    if isinstance(clause, Grouping):
        yield from _conjuncts(cast(ClauseElement, clause.element))
    elif isinstance(clause, BooleanClauseList) and clause.operator is operators.and_:
        for term in clause.clauses:
            yield from _conjuncts(term)
    else:
        yield clause


def _bind_value(element: ClauseElement) -> object:
    if isinstance(element, BindParameter):
        return element.effective_value
    return _UNKNOWN


def _short_sql(statement: ClauseElement) -> str:
    try:
        sql = " ".join(str(statement).split())
    except Exception:  # noqa: BLE001 - compiling is best effort, only for the message
        sql = type(statement).__name__
    return sql if len(sql) <= _MAX_SQL_IN_MESSAGE else sql[:_MAX_SQL_IN_MESSAGE] + "..."


class TenantGuard:
    """Scope statements on tenant-scoped tables to the session's tenant.

    Args:
        models: mapped classes, declarative mixins/abstract bases (every mapped
            subclass is covered, including ones declared after the guard), or Core
            ``Table`` objects that are tenant-scoped.
        column: name of the tenant column on those tables.
        strict: raise :class:`UnscopedQueryError` / :class:`CrossTenantQueryError`
            instead of reporting and correcting the statement.
        on_violation: called for each corrected statement in permissive mode
            (default: a ``logging`` warning on the ``tenant_isolation_kit`` logger).
        tenant_resolver: returns the tenant for a session; default reads
            ``session.info[TENANT_INFO_KEY]`` and falls back to :func:`tenant_scope`.
    """

    def __init__(
        self,
        models: Iterable[type[Any] | Table],
        *,
        column: str = "tenant_id",
        strict: bool = True,
        on_violation: Callable[[Violation], None] | None = None,
        tenant_resolver: Callable[[Session], Hashable | None] | None = None,
    ) -> None:
        self._roots: tuple[type[Any] | Table, ...] = tuple(models)
        if not self._roots:
            raise ValueError("TenantGuard needs at least one tenant-scoped model or table")
        self.column = column
        self.strict = strict
        self._on_violation = on_violation or _default_on_violation
        self._resolve: Callable[[Session], Hashable | None] = tenant_resolver or (
            lambda session: current_tenant(session.info)
        )
        self._text_patterns: dict[str, re.Pattern[str]] = {}

    # -- installation ---------------------------------------------------------

    def install(self, target: InstallTarget) -> TenantGuard:
        """Listen on a Session class, a ``sessionmaker`` or a single Session."""
        event.listen(target, "do_orm_execute", self._on_execute)
        event.listen(target, "before_flush", self._on_flush)
        return self

    def uninstall(self, target: InstallTarget) -> None:
        event.remove(target, "do_orm_execute", self._on_execute)
        event.remove(target, "before_flush", self._on_flush)

    # -- registry -------------------------------------------------------------

    def tenant_tables(self) -> dict[int, _TenantTable]:
        """Tenant tables keyed by ``hash(table)``.

        Recomputed on each call so that models declared after the guard was built are
        covered. Keys are hashes because ORM statements hold *annotated* copies of
        tables and columns, which hash like the original but do not compare equal.
        """
        found: dict[int, _TenantTable] = {}
        for root in self._roots:
            if isinstance(root, Table):
                self._add_table(found, root, None)
                continue
            for cls in self._walk(root):
                mapper = inspect(cls, raiseerr=False)
                if not isinstance(mapper, Mapper):
                    continue
                tables = [t for t in mapper.tables if isinstance(t, Table) and self.column in t.c]
                if not tables:
                    raise TypeError(
                        f"{cls.__name__} is registered as tenant-scoped but none of its "
                        f"tables has a {self.column!r} column"
                    )
                for table in tables:
                    self._add_table(found, table, cls)
        return found

    @staticmethod
    def _walk(root: type[Any]) -> Iterator[type[Any]]:
        stack, seen = [root], set()
        while stack:
            cls = stack.pop()
            if cls in seen:
                continue
            seen.add(cls)
            yield cls
            stack.extend(cls.__subclasses__())

    def _add_table(
        self, found: dict[int, _TenantTable], table: Table, cls: type[Any] | None
    ) -> None:
        if self.column not in table.c:
            raise TypeError(f"table {table.name!r} has no {self.column!r} column")
        key = hash(table)
        previous = found.get(key)
        classes = previous.classes if previous else ()
        if cls is not None and cls not in classes:
            classes = (*classes, cls)
        found[key] = _TenantTable(table, table.c[self.column], classes)

    # -- do_orm_execute -------------------------------------------------------

    def _on_execute(self, state: ORMExecuteState) -> None:
        session = state.session
        if state.is_column_load or is_bypassed(session.info):
            return
        if state.execution_options.get(BYPASS_OPTION):
            return
        registry = self.tenant_tables()
        # Every executable statement SQLAlchemy hands to do_orm_execute is a ClauseElement.
        statement = cast(ClauseElement, state.statement)
        touched, texts = self._scan(statement, registry)
        text_hits = [t for t in texts if self._text_touches(t, registry)]
        if not touched and not text_hits:
            return
        tenant = self._resolve(session)
        if tenant is None:
            names = sorted(registry[k].table.name for k in touched) + ["text()"] * bool(text_hits)
            raise MissingTenantContextError(
                f"statement touches tenant-scoped {', '.join(names)} but no tenant is "
                f"bound to the session: {_short_sql(statement)}"
            )

        corrected = not text_hits and self._can_scope(statement, touched, registry)
        if not state.is_relationship_load:
            self._check_predicates(statement, touched, registry, tenant, corrected=corrected)
        for clause in text_hits:
            self._check_text(clause, registry, tenant, state.parameters)
        if state.is_insert:
            self._check_insert_params(touched, registry, tenant, state.parameters)
            return
        if state.is_executemany and (state.is_update or state.is_delete):
            # ORM bulk UPDATE/DELETE by primary key cannot synchronize the identity map
            # once extra WHERE criteria are present.
            state.update_execution_options(synchronize_session=None)
        state.statement = self._scoped(statement, touched, registry, tenant)

    @staticmethod
    def _can_scope(
        statement: ClauseElement, touched: set[int], registry: Mapping[int, _TenantTable]
    ) -> bool:
        if isinstance(statement, (Update, Delete)):
            return touched == {hash(statement.table)}
        return all(registry[key].classes for key in touched)

    @staticmethod
    def _scan(
        statement: ClauseElement, registry: Mapping[int, _TenantTable]
    ) -> tuple[set[int], list[TextClause]]:
        touched: set[int] = set()
        texts: list[TextClause] = []
        for element in visitors.iterate(statement):
            if isinstance(element, TableClause) and hash(element) in registry:
                touched.add(hash(element))
            elif isinstance(element, TextClause):
                texts.append(element)
        return touched, texts

    def _tenant_column_table(
        self, element: ClauseElement, registry: Mapping[int, _TenantTable]
    ) -> int | None:
        """``hash(table)`` if ``element`` is (an alias or annotation of) a tenant column."""
        if not isinstance(element, ColumnElement):
            return None
        tenant_columns = {hash(t.column): key for key, t in registry.items()}
        for proxied in element.proxy_set:
            key = tenant_columns.get(hash(proxied))
            if key is not None:
                return key
        return None

    def _predicates(
        self, statement: ClauseElement, registry: Mapping[int, _TenantTable]
    ) -> dict[int, list[object]]:
        """Explicit tenant predicates, per table, with the compared values."""
        found: dict[int, list[object]] = {}
        for element in visitors.iterate(statement):
            where = getattr(element, "whereclause", None)
            for term in _conjuncts(where):
                if not isinstance(term, BinaryExpression):
                    continue
                if term.operator not in (operators.eq, operators.in_op):
                    continue
                for col_side, value_side in ((term.left, term.right), (term.right, term.left)):
                    key = self._tenant_column_table(col_side, registry)
                    if key is None or isinstance(value_side, ColumnClause):
                        # col = other_col (a join condition) does not pin a tenant
                        continue
                    found.setdefault(key, []).append(_bind_value(value_side))
                    break
        return found

    def _check_predicates(
        self,
        statement: ClauseElement,
        touched: set[int],
        registry: Mapping[int, _TenantTable],
        tenant: Hashable,
        *,
        corrected: bool,
    ) -> None:
        predicates = self._predicates(statement, registry)
        missing = sorted(registry[k].table.name for k in touched if k not in predicates)
        if missing:
            self._violation(
                "unscoped",
                UnscopedQueryError,
                missing,
                statement,
                f"no explicit {self.column} predicate for {', '.join(missing)}",
                corrected=corrected,
            )
        for key, values in predicates.items():
            for value in values:
                if self._is_foreign(value, tenant):
                    name = registry[key].table.name
                    self._violation(
                        "cross_tenant",
                        CrossTenantQueryError,
                        [name],
                        statement,
                        f"{name}.{self.column} is compared with {value!r}, "
                        f"but the session is bound to tenant {tenant!r}",
                        corrected=corrected,
                    )

    @staticmethod
    def _is_foreign(value: object, tenant: Hashable) -> bool:
        if value is _UNKNOWN:
            return False
        if isinstance(value, (list, tuple, set, frozenset)):
            return any(v != tenant for v in value)
        return value != tenant

    def _text_pattern(self, name: str) -> re.Pattern[str]:
        pattern = self._text_patterns.get(name)
        if pattern is None:
            pattern = re.compile(rf"(?<![\w.]){re.escape(name)}(?!\w)", re.IGNORECASE)
            self._text_patterns[name] = pattern
        return pattern

    def _text_touches(self, clause: TextClause, registry: Mapping[int, _TenantTable]) -> bool:
        return any(self._text_pattern(t.table.name).search(clause.text) for t in registry.values())

    def _check_text(
        self,
        clause: TextClause,
        registry: Mapping[int, _TenantTable],
        tenant: Hashable,
        parameters: object,
    ) -> None:
        """Heuristic for ``text()``: a tenant table name appears in the SQL, so the
        tenant column must appear too, and a bound ``:<column>`` must be our tenant."""
        names = sorted(
            t.table.name
            for t in registry.values()
            if self._text_pattern(t.table.name).search(clause.text)
        )
        if not self._text_pattern(self.column).search(clause.text):
            self._violation(
                "unscoped",
                UnscopedQueryError,
                names,
                clause,
                f"text() SQL mentions {', '.join(names)} but never {self.column}",
                corrected=False,
            )
            return
        for params in self._param_sets(parameters):
            value = params.get(self.column, _UNKNOWN)
            if self._is_foreign(value, tenant):
                self._violation(
                    "cross_tenant",
                    CrossTenantQueryError,
                    names,
                    clause,
                    f"text() binds {self.column}={value!r}, session tenant is {tenant!r}",
                    corrected=False,
                )

    @staticmethod
    def _param_sets(parameters: object) -> list[Mapping[str, Any]]:
        if isinstance(parameters, Mapping):
            return [parameters]
        if isinstance(parameters, Sequence) and not isinstance(parameters, (str, bytes)):
            return [p for p in parameters if isinstance(p, Mapping)]
        return []

    def _check_insert_params(
        self,
        touched: set[int],
        registry: Mapping[int, _TenantTable],
        tenant: Hashable,
        parameters: object,
    ) -> None:
        names = sorted(registry[k].table.name for k in touched)
        for params in self._param_sets(parameters):
            value = params.get(self.column, _UNKNOWN)
            if self._is_foreign(value, tenant):
                raise CrossTenantWriteError(
                    f"bulk insert into {', '.join(names)} with {self.column}={value!r}, "
                    f"but the session is bound to tenant {tenant!r}"
                )

    def _violation(
        self,
        kind: ViolationKind,
        error: type[TenantIsolationError],
        tables: Sequence[str],
        statement: ClauseElement,
        detail: str,
        *,
        corrected: bool,
    ) -> None:
        sql = _short_sql(statement)
        message = f"{detail}: {sql}"
        if self.strict:
            raise error(message)
        self._on_violation(Violation(kind, tuple(tables), sql, message, corrected))

    def _scoped(
        self,
        statement: Any,
        touched: set[int],
        registry: Mapping[int, _TenantTable],
        tenant: Hashable,
    ) -> Any:
        if isinstance(statement, (Update, Delete)):
            target = hash(statement.table)
            if target in registry:
                statement = statement.where(registry[target].column == tenant)
            return statement
        options = [
            with_loader_criteria(cls, getattr(cls, self._attr(cls)) == tenant, include_aliases=True)
            for key in sorted(touched)
            for cls in registry[key].classes
        ]
        if options and hasattr(statement, "options"):
            statement = statement.options(*options)
        return statement

    def _attr(self, cls: type[Any]) -> str:
        """Mapped attribute name of the tenant column (it may differ from the column name)."""
        mapper: Mapper[Any] = inspect(cls)
        for table in mapper.tables:
            if self.column in table.c:
                return mapper.get_property_by_column(table.c[self.column]).key
        raise TypeError(f"{cls.__name__} has no {self.column!r} column")  # pragma: no cover

    # -- before_flush ---------------------------------------------------------

    def _on_flush(self, session: Session, flush_context: object, instances: object) -> None:
        if is_bypassed(session.info):
            return
        registry = self.tenant_tables()
        scoped_classes = {cls for t in registry.values() for cls in t.classes}
        pending = [
            obj
            for obj in (*session.new, *session.dirty)
            if any(isinstance(obj, cls) for cls in scoped_classes)
        ]
        if not pending:
            return
        tenant = self._resolve(session)
        if tenant is None:
            raise MissingTenantContextError(
                f"flushing {len(pending)} tenant-scoped object(s) with no tenant bound"
            )
        for obj in pending:
            attr = self._attr(type(obj))
            value = getattr(obj, attr)
            if value is None:
                setattr(obj, attr, tenant)
            elif value != tenant:
                raise CrossTenantWriteError(
                    f"{type(obj).__name__}.{attr}={value!r} written by a session bound "
                    f"to tenant {tenant!r}"
                )
