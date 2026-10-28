"""Cross-tenant test matrix, independent of the test runner.

Given the routes of an app and a :class:`Resource` description, :func:`build_cases`
derives one :class:`Case` per (route, attack). Each case is run with two
authenticated clients: tenant A (the victim) creates a resource that carries a
random *canary* string, then tenant B (the attacker) attacks it. A case reports a
:class:`Finding` when

* B is not denied (status outside ``Resource.denied``, by default 403/404) on a
  route that addresses A's resource by id;
* any response B receives contains A's canary (a leak through a list, an export,
  a cache, an error message...);
* after a write by B, A can no longer read its resource, or reads B's canary in it;
* a tenant id forged by B (body field, query parameter or header) puts B's data in
  A's view, or A's data in B's.

Before the attack the owner performs the same read, and the case is reported as
*vacuous* (:class:`VacuousCaseError`) if A cannot see its own canary: a check that
cannot fail proves nothing.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Collection, Hashable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

__all__ = [
    "Case",
    "CaseKind",
    "Finding",
    "HTTPClient",
    "IsolationFailure",
    "MatrixSetupError",
    "Resource",
    "Route",
    "Tenant",
    "TenantPair",
    "VacuousCaseError",
    "build_cases",
    "discover_routes",
]

SAFE_METHODS = frozenset({"GET"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_PATH_PARAM = re.compile(r"{(\w+)(?::[^}]*)?}")

CaseKind = Literal["read", "write", "list", "forge-query", "forge-header", "forge-body"]


class HTTPResponse(Protocol):
    @property
    def status_code(self) -> int: ...
    @property
    def text(self) -> str: ...
    def json(self) -> Any: ...


class HTTPClient(Protocol):
    """Anything shaped like ``httpx.Client`` or Starlette's ``TestClient``."""

    def request(self, method: str, url: str, **kwargs: Any) -> HTTPResponse: ...


@dataclass(frozen=True)
class Tenant:
    tenant_id: Hashable
    client: HTTPClient


@dataclass(frozen=True)
class TenantPair:
    """``a`` owns the data, ``b`` attacks it. Both must be authenticated already."""

    a: Tenant
    b: Tenant


@dataclass(frozen=True)
class Resource:
    """How to create one tenant-owned resource and where its routes live.

    Args:
        name: label used in test ids and reports.
        collection: path of the create (``POST``) route, e.g. ``"/notes"``. Every
            route equal to it or below it belongs to the resource.
        create: builds the JSON body for the create request from a canary string;
            put the canary in a field the API echoes back.
        id_field: field of the create response that holds the new id.
        path_params: maps a path parameter to the create-response field that fills
            it; parameters not listed are filled with ``id_field``.
        update: JSON body for ``PUT``/``PATCH``/``POST`` attacks (default: ``create``).
        tenant_field: body/query field an attacker might use to name a tenant.
        tenant_header: header an attacker might use to name a tenant.
        denied: status codes that count as a denial for B.
        exclude: ``(METHOD, path)`` pairs to leave out, e.g. deliberately public routes.
    """

    name: str
    collection: str
    create: Callable[[str], Mapping[str, Any]]
    id_field: str = "id"
    path_params: Mapping[str, str] = field(default_factory=dict)
    update: Callable[[str], Mapping[str, Any]] | None = None
    tenant_field: str | None = None
    tenant_header: str | None = None
    denied: frozenset[int] = frozenset({403, 404})
    exclude: Collection[tuple[str, str]] = ()


@dataclass(frozen=True, order=True)
class Route:
    path: str
    method: str


@dataclass(frozen=True)
class Finding:
    case_id: str
    message: str


class MatrixSetupError(AssertionError):
    """The matrix could not set the case up (for example, A failed to create)."""


class IsolationFailure(AssertionError):
    """Raised by :meth:`Case.check` when tenant B could reach tenant A's data."""

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        lines = "\n".join(f"  - {f.message}" for f in findings)
        super().__init__(f"cross-tenant access in {findings[0].case_id}:\n{lines}")


class VacuousCaseError(AssertionError):
    """The owner cannot see its own canary, so the cross-tenant check would be void."""


def discover_routes(app: Any) -> list[Route]:
    """Routes of a FastAPI/Starlette app (anything with ``.routes`` of ``.path``/``.methods``)."""
    routes: set[Route] = set()
    for route in getattr(app, "routes", ()):
        path, methods = getattr(route, "path", None), getattr(route, "methods", None)
        if not isinstance(path, str) or not methods:
            continue
        routes.update(
            Route(path, m.upper()) for m in methods if m.upper() in SAFE_METHODS | WRITE_METHODS
        )
    return sorted(routes)


def _belongs(route: Route, collection: str) -> bool:
    prefix = collection.rstrip("/")
    return route.path == prefix or route.path.startswith(prefix + "/")


def build_cases(resources: Iterable[Resource], routes: Iterable[Route]) -> list[Case]:
    routes = sorted(routes)
    cases: list[Case] = []
    for resource in resources:
        for route in routes:
            if not _belongs(route, resource.collection):
                continue
            if (route.method, route.path) in resource.exclude:
                continue
            for kind in _kinds(resource, route):
                cases.append(Case(resource, route, kind, routes=tuple(routes)))
    return cases


def _kinds(resource: Resource, route: Route) -> list[CaseKind]:
    if _PATH_PARAM.search(route.path):
        return ["read" if route.method in SAFE_METHODS else "write"]
    kinds: list[CaseKind] = []
    if route.method in SAFE_METHODS:
        kinds.append("list")
        if resource.tenant_field:
            kinds.append("forge-query")
        if resource.tenant_header:
            kinds.append("forge-header")
    elif route.method == "POST" and route.path == resource.collection.rstrip("/"):
        if resource.tenant_field or resource.tenant_header:
            kinds.append("forge-body")
    # Other collection-level writes (bulk actions) need a request body the matrix
    # cannot infer; cover them with a hand-written test or the runtime guard.
    return kinds


def _fmt(value: object) -> str:
    return str(value)


@dataclass(frozen=True)
class Case:
    resource: Resource
    route: Route
    kind: CaseKind
    routes: tuple[Route, ...] = ()

    @property
    def id(self) -> str:
        return f"{self.resource.name}:{self.kind}:{self.route.method} {self.route.path}"

    # -- helpers -------------------------------------------------------------

    def _create(self, tenant: Tenant, canary: str, **extra: Any) -> tuple[HTTPResponse, Any]:
        body = {**self.resource.create(canary), **extra.pop("json_extra", {})}
        response = tenant.client.request("POST", self.resource.collection, json=body, **extra)
        if not 200 <= response.status_code < 300:
            return response, None
        return response, response.json()

    def _fill(self, path: str, created: Mapping[str, Any]) -> str:
        def value(match: re.Match[str]) -> str:
            name = match.group(1)
            source = self.resource.path_params.get(name, self.resource.id_field)
            if source not in created:
                raise MatrixSetupError(
                    f"{self.id}: create response has no field {source!r} for path "
                    f"parameter {{{name}}}; set Resource.path_params"
                )
            return _fmt(created[source])

        return _PATH_PARAM.sub(value, path)

    def _item_read_path(self, created: Mapping[str, Any]) -> str | None:
        """Path of the plain ``GET <collection>/{id}`` route, used for integrity checks."""
        prefix = self.resource.collection.rstrip("/")
        for route in self.routes:
            rest = route.path[len(prefix) :]
            if (
                route.method == "GET"
                and route.path.startswith(prefix)
                and re.fullmatch(r"/{\w+}", rest)
            ):
                return self._fill(route.path, created)
        return None

    def _owner_view(self, pair: TenantPair, path: str, canary: str, **kwargs: Any) -> str:
        response = pair.a.client.request("GET", path, **kwargs)
        if not 200 <= response.status_code < 300 or canary not in response.text:
            raise VacuousCaseError(
                f"{self.id}: tenant A gets HTTP {response.status_code} for its own "
                f"GET {path} and does not see its canary; the cross-tenant check would "
                "prove nothing (fix the Resource description or exclude the route)"
            )
        return response.text

    # -- run -----------------------------------------------------------------

    def run(self, pair: TenantPair) -> list[Finding]:
        """Execute the case and return what leaked (empty list: isolated)."""
        canary_a = f"tik-a-{secrets.token_hex(6)}"
        canary_b = f"tik-b-{secrets.token_hex(6)}"
        response, created = self._create(pair.a, canary_a)
        if created is None:
            raise MatrixSetupError(
                f"{self.id}: tenant A could not create {self.resource.name} "
                f"(POST {self.resource.collection} -> HTTP {response.status_code})"
            )
        if self.kind == "forge-body":
            return self._run_forge_body(pair, created, canary_a, canary_b)

        path = self._fill(self.route.path, created)
        kwargs: dict[str, Any] = {}
        if self.kind == "forge-query":
            kwargs["params"] = {self.resource.tenant_field: _fmt(pair.a.tenant_id)}
        elif self.kind == "forge-header":
            kwargs["headers"] = {self.resource.tenant_header: _fmt(pair.a.tenant_id)}
        elif self.kind == "write" and self.route.method != "DELETE":
            kwargs["json"] = dict((self.resource.update or self.resource.create)(canary_b))

        if self.kind != "write":
            # The owner reads first: proves the check is not vacuous and warms any
            # cache that a later cross-tenant read could be served from.
            self._owner_view(pair, path, canary_a)

        attack = pair.b.client.request(self.route.method, path, **kwargs)
        findings: list[Finding] = []
        where = f"{self.route.method} {path}"
        if self.kind in ("read", "write") and attack.status_code not in self.resource.denied:
            expected = " or ".join(str(c) for c in sorted(self.resource.denied))
            findings.append(
                self._finding(
                    f"tenant B got HTTP {attack.status_code} for {where} on tenant A's "
                    f"{self.resource.name} (expected {expected})"
                )
            )
        if canary_a in attack.text:
            findings.append(
                self._finding(f"tenant B's response to {where} contains tenant A's data")
            )
        if self.kind == "write":
            findings.extend(self._integrity(pair, created, canary_a, canary_b, where))
        return findings

    def check(self, pair: TenantPair) -> None:
        """Run the case and raise :class:`IsolationFailure` on any finding."""
        findings = self.run(pair)
        if findings:
            raise IsolationFailure(findings)

    def _integrity(
        self, pair: TenantPair, created: Mapping[str, Any], canary_a: str, canary_b: str, where: str
    ) -> list[Finding]:
        item = self._item_read_path(created)
        if item is None:
            return []
        response = pair.a.client.request("GET", item)
        if not 200 <= response.status_code < 300:
            return [
                self._finding(
                    f"after tenant B's {where}, tenant A gets HTTP "
                    f"{response.status_code} for its own GET {item}"
                )
            ]
        if canary_b in response.text or canary_a not in response.text:
            return [
                self._finding(
                    f"after tenant B's {where}, tenant A's {self.resource.name} "
                    "was modified by tenant B"
                )
            ]
        return []

    def _run_forge_body(
        self, pair: TenantPair, created: Mapping[str, Any], canary_a: str, canary_b: str
    ) -> list[Finding]:
        extra: dict[str, Any] = {}
        how = []
        if self.resource.tenant_field:
            extra["json_extra"] = {self.resource.tenant_field: pair.a.tenant_id}
            how.append(f"body field {self.resource.tenant_field!r}")
        if self.resource.tenant_header:
            extra["headers"] = {self.resource.tenant_header: _fmt(pair.a.tenant_id)}
            how.append(f"header {self.resource.tenant_header!r}")
        self._create(pair.b, canary_b, **extra)
        view = self._owner_view(pair, self.resource.collection, canary_a)
        if canary_b in view:
            return [
                self._finding(
                    f"tenant B planted a {self.resource.name} in tenant A's data "
                    f"by naming tenant A in the {' and '.join(how)}"
                )
            ]
        return []

    def _finding(self, message: str) -> Finding:
        return Finding(self.id, message)
