"""Catch cross-tenant access (IDOR/BOLA) in FastAPI + SQLAlchemy applications.

Three independent layers:

* ``semgrep/`` rules flag risky code patterns before review;
* :mod:`tenant_isolation_kit.matrix` and its pytest plugin attack every route
  with a second tenant;
* :class:`TenantGuard` scopes and checks every ORM statement at runtime.
"""

from __future__ import annotations

from tenant_isolation_kit.context import (
    BYPASS_INFO_KEY,
    BYPASS_OPTION,
    TENANT_INFO_KEY,
    bypass_tenant_guard,
    current_tenant,
    tenant_scope,
)
from tenant_isolation_kit.errors import (
    CrossTenantQueryError,
    CrossTenantWriteError,
    MissingTenantContextError,
    TenantIsolationError,
    UnscopedQueryError,
)
from tenant_isolation_kit.guard import TenantGuard, Violation
from tenant_isolation_kit.matrix import (
    Case,
    Finding,
    IsolationFailure,
    Resource,
    Route,
    Tenant,
    TenantPair,
    build_cases,
    discover_routes,
)

__version__ = "0.1.0"

__all__ = [
    "BYPASS_INFO_KEY",
    "BYPASS_OPTION",
    "TENANT_INFO_KEY",
    "Case",
    "CrossTenantQueryError",
    "CrossTenantWriteError",
    "Finding",
    "IsolationFailure",
    "MissingTenantContextError",
    "Resource",
    "Route",
    "Tenant",
    "TenantGuard",
    "TenantIsolationError",
    "TenantPair",
    "UnscopedQueryError",
    "Violation",
    "__version__",
    "build_cases",
    "bypass_tenant_guard",
    "current_tenant",
    "discover_routes",
    "tenant_scope",
]
