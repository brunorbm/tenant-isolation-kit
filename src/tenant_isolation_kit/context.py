"""Where the runtime guard learns the current tenant.

The recommended binding is per session: create the request's session with
``info={TENANT_INFO_KEY: principal.tenant_id}``. A session is already request-scoped
in most FastAPI apps, and session ``info`` survives the thread hops that sync
dependencies make, which a :class:`contextvars.ContextVar` set inside a dependency
does not.

For code that has no request-scoped session (workers, scripts), :func:`tenant_scope`
binds a tenant through a context variable instead. The session binding wins when both
are present.
"""

from __future__ import annotations

from collections.abc import Hashable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

__all__ = [
    "BYPASS_INFO_KEY",
    "BYPASS_OPTION",
    "TENANT_INFO_KEY",
    "bypass_tenant_guard",
    "current_tenant",
    "is_bypassed",
    "tenant_scope",
]

#: ``Session.info`` key holding the tenant the session acts for.
TENANT_INFO_KEY = "tenant_isolation_kit.tenant_id"
#: ``Session.info`` key that, when truthy, disables the guard for the whole session.
BYPASS_INFO_KEY = "tenant_isolation_kit.bypass"
#: Execution option that disables the guard for one statement.
BYPASS_OPTION = "tenant_isolation_kit_bypass"

_tenant: ContextVar[Hashable | None] = ContextVar("tenant_isolation_kit_tenant", default=None)
_bypass: ContextVar[str | None] = ContextVar("tenant_isolation_kit_bypass", default=None)


def current_tenant(info: dict[Any, Any] | None = None) -> Hashable | None:
    """Return the tenant bound in ``info`` (a ``Session.info``), else in the context."""
    if info is not None and info.get(TENANT_INFO_KEY) is not None:
        tenant: Hashable = info[TENANT_INFO_KEY]
        return tenant
    return _tenant.get()


@contextmanager
def tenant_scope(tenant_id: Hashable) -> Iterator[None]:
    """Bind ``tenant_id`` for the duration of the ``with`` block (context variable)."""
    if tenant_id is None:
        raise ValueError("tenant_scope() needs a tenant id, got None")
    token = _tenant.set(tenant_id)
    try:
        yield
    finally:
        _tenant.reset(token)


@contextmanager
def bypass_tenant_guard(reason: str) -> Iterator[None]:
    """Disable the guard inside the block, for deliberate cross-tenant work.

    ``reason`` is mandatory and non-empty so that every bypass is greppable and
    explains itself in review (for example ``"nightly billing rollup"``).
    """
    if not reason.strip():
        raise ValueError("bypass_tenant_guard() needs a non-empty reason")
    token = _bypass.set(reason)
    try:
        yield
    finally:
        _bypass.reset(token)


def is_bypassed(info: dict[Any, Any] | None = None) -> bool:
    """True when the guard is disabled by the context or by the session's ``info``."""
    if _bypass.get() is not None:
        return True
    return bool(info and info.get(BYPASS_INFO_KEY))
