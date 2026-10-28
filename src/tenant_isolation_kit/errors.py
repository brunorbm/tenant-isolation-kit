"""Exception hierarchy.

Every error raised by the runtime guard derives from :class:`TenantIsolationError`,
so an application can map all of them to a single HTTP 500 (they indicate a bug in
the application, never a client mistake) and alert on them.
"""

from __future__ import annotations

__all__ = [
    "CrossTenantQueryError",
    "CrossTenantWriteError",
    "MissingTenantContextError",
    "TenantIsolationError",
    "UnscopedQueryError",
]


class TenantIsolationError(RuntimeError):
    """Base class: a statement would have crossed, or could cross, a tenant boundary."""


class MissingTenantContextError(TenantIsolationError):
    """A tenant-scoped table was queried while no tenant was bound to the session."""


class UnscopedQueryError(TenantIsolationError):
    """A statement touches a tenant-scoped table without an explicit tenant predicate.

    Raised only in strict mode. In permissive mode the guard still injects the
    tenant filter, and reports the statement through ``on_violation`` instead.
    """


class CrossTenantQueryError(TenantIsolationError):
    """An explicit tenant predicate names a tenant other than the bound one."""


class CrossTenantWriteError(TenantIsolationError):
    """A row is being written with a ``tenant_id`` other than the bound tenant."""
