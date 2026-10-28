# tenant-isolation-kit

[![CI](https://github.com/brunorbm/tenant-isolation-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/brunorbm/tenant-isolation-kit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/brunorbm/tenant-isolation-kit/actions/workflows/codeql.yml/badge.svg)](https://github.com/brunorbm/tenant-isolation-kit/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.10-3.13](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)
![Typed: mypy --strict](https://img.shields.io/badge/typing-mypy%20--strict-informational.svg)

This kit finds and stops cross-tenant data access in multi-tenant **FastAPI + SQLAlchemy 2.x**
services. That bug class is known as IDOR or BOLA:
[CWE-639](https://cwe.mitre.org/data/definitions/639.html),
[CWE-284](https://cwe.mitre.org/data/definitions/284.html) and
[OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).

It has three independent layers. Each one catches bugs that the other two miss:

| Layer | When it runs | What it does |
|---|---|---|
| **Semgrep rules** (`semgrep/`) | review, CI | Flags query shapes that are known to leak: primary-key lookups with no owner predicate, raw SQL with no tenant predicate, bulk writes filtered by id only, and a tenant id taken from the request. |
| **pytest matrix** (`tenant_matrix` marker) | test suite | Generates one test per (route, attack) from the app's routes. Tenant A plants a random canary, then tenant B tries to read, overwrite, delete or forge its way to it. |
| **Runtime guard** (`TenantGuard`) | every statement, in production | Hooks the SQLAlchemy `Session`, so that every statement on a tenant-scoped table is scoped to the bound tenant. In strict mode, a statement without an explicit tenant predicate raises. |

## The problem

In a shared-schema multi-tenant app, each tenant-owned row has a `tenant_id`, and *every* query
must filter on it. Nothing in SQLAlchemy or FastAPI enforces this. One handler that writes
`session.get(Invoice, invoice_id)` is enough to make every invoice readable by every customer
who can guess an integer. These bugs:

- look like correct code in review, because the missing line is the bug;
- pass functional tests, which use one tenant at a time;
- are found by attackers, who enumerate ids as soon as they have an account.

## Threat model

**Attacker:** a legitimate, authenticated user of tenant B. They know the API, can send any
request, and can learn or guess identifiers of tenant A's objects: sequential ids, business
keys such as invoice numbers, and ids leaked in URLs or emails.

**Goal:** read, modify, delete or create data in tenant A, or make tenant A see data that B
planted.

**In scope:**
- object lookups by id or business key;
- list and export endpoints;
- bulk writes;
- tenant selectors that the client controls (body field, query parameter, header);
- per-object response caches.

**Out of scope:**
- authentication itself; the kit assumes the principal is genuine;
- SQL injection;
- side channels such as timing and row counts in error messages;
- access control *within* a tenant (user versus admin);
- a compromised database or application server.

## Quickstart

```bash
# Not on PyPI yet: install from a checkout.
pip install -e .                            # the guard and the pytest plugin
pip install semgrep                         # for the rules (optional)
```

**1. Runtime guard.** Bind the request's session to the caller's tenant and install the guard
once:

```python
from tenant_isolation_kit import TENANT_INFO_KEY, TenantGuard

guard = TenantGuard([TenantScoped], strict=True)   # TenantScoped: your abstract base
guard.install(SessionLocal)                         # a sessionmaker, or a Session subclass

def get_session(principal: CurrentPrincipal) -> Iterator[Session]:
    with SessionLocal(info={TENANT_INFO_KEY: principal.tenant_id}) as session:
        yield session
```

Every guard error derives from `TenantIsolationError`. Map that class to an HTTP 500 and alert on
it, because it always means an application bug. `strict=False` scopes the statement and
reports it through `on_violation`, which logs a warning by default. It is the mode for
rolling the guard out to an existing codebase. To do cross-tenant work on purpose, wrap it in
`bypass_tenant_guard("nightly billing rollup")`. The reason argument is mandatory, so every
bypass can be found with grep.

**2. Cross-tenant matrix.** Describe each resource once, and provide a `tenant_pair` fixture
with two clients that are authenticated as different tenants:

```python
from tenant_isolation_kit import Resource, Tenant, TenantPair

NOTES = Resource("note", "/notes", create=lambda canary: {"body": canary},
                 tenant_field="tenant_id")

@pytest.fixture
def tenant_pair() -> TenantPair:
    return TenantPair(a=Tenant("acme", alice_client), b=Tenant("globex", bob_client))

@pytest.mark.tenant_matrix(app=app, resources=[NOTES])
def test_cross_tenant(cross_tenant_case, tenant_pair):
    cross_tenant_case.check(tenant_pair)
```

Each case runs as its own test, with an id such as `note:read:GET /notes/{note_id}`. A case also
fails as *vacuous* if tenant A cannot see its own canary, because a check that cannot fail
proves nothing.

**3. Semgrep rules.**

```bash
semgrep scan --metrics=off --config semgrep/ src/
```

Each rule records its false-positive and false-negative tradeoffs under `metadata.tradeoffs`.

## Seeded bugs: which layer catches what

`examples/vulnerable_app` is a small notes-and-invoices API with ten seeded bugs.
`examples/fixed_app` is the same API, fixed. The table is generated from
`examples/seeded_bugs.py`. The tests assert each cell in both directions, so a "-" is a
verified miss rather than an untested one:

- `tests/test_semgrep_rules.py` checks the Semgrep column;
- `tests/test_seeded_bugs.py` checks the matrix and guard columns.

<!-- seeded-bugs:start -->
| Bug | Route | Flaw | CWE | Semgrep | Matrix | Guard (strict) |
|---|---|---|---|---|---|---|
| V1 | `GET /notes/{note_id}` | `session.get(Note, id)` with no ownership check | CWE-639 | `tik-unscoped-pk-lookup`<br>`tik-path-param-lookup-without-ownership-check` | caught | caught |
| V2 | `PATCH /notes/{note_id}` | `select(Note).where(Note.id == id)` then update | CWE-639 | `tik-unscoped-pk-lookup`<br>`tik-path-param-lookup-without-ownership-check` | caught | caught |
| V3 | `DELETE /notes/{note_id}` | Core `delete(Note).where(Note.id == id)` | CWE-639 | `tik-bulk-write-without-tenant-filter`<br>`tik-path-param-lookup-without-ownership-check` | caught | caught |
| V4 | `GET /notes/export` | raw `text()` SQL with no tenant predicate | CWE-284 | `tik-raw-sql-without-tenant-predicate` | caught | caught |
| V5 | `GET /notes?tenant_id=` | tenant chosen by a query parameter | CWE-639 | `tik-tenant-id-from-request` | caught | caught |
| V6 | `POST /notes` | owner taken from the request body | CWE-639 | `tik-tenant-id-from-request` | caught | caught |
| V7 | `POST /invoices/mark-paid` | bulk Core `table.update()` filtered by id only | CWE-639 | - | - | caught |
| V8 | `GET /invoices/{invoice_id}/receipt` | response cache keyed by invoice id, not (tenant, id) | CWE-524 | - | caught | - |
| V9 | `GET /invoices/by-number/{number}` | lookup by a per-tenant business key | CWE-639 | - | caught | caught |
| V10 | `GET /invoices (X-Tenant-ID)` | tenant chosen by a client header | CWE-639 | `tik-tenant-id-from-request` | caught | caught |
<!-- seeded-bugs:end -->

No single layer catches everything:

- **V7:** the table object comes from `metadata.tables[...]`, which Semgrep cannot connect to a
  model.
- **V8:** the leak is in an application cache, which the guard never sees.
- **V9:** the lookup key is a business key, not a primary key, so the rules do not fire.

All three layers pass on the fixed app. The fixed app runs the full matrix under the strict
guard.

## CWE / OWASP mapping

| Weakness | Where |
|---|---|
| [CWE-639](https://cwe.mitre.org/data/definitions/639.html) Authorization bypass through user-controlled key | All five rules, all matrix cases, the guard |
| [CWE-284](https://cwe.mitre.org/data/definitions/284.html) Improper access control | `tik-raw-sql-without-tenant-predicate`, `tik-bulk-write-without-tenant-filter`, `tik-path-param-lookup-without-ownership-check`, the guard |
| [CWE-524](https://cwe.mitre.org/data/definitions/524.html) Sensitive information in a cache | Matrix `read` cases (the owner reads first, which warms the cache) |
| [OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) Broken object level authorization | All three layers |
| [OWASP A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) Broken access control | All three layers |

## Limitations

- **The guard only sees statements that go through a `Session`.** It does not see:
  - `engine.connect()`;
  - raw DB-API cursors;
  - Alembic migrations;
  - other processes.

  It knows nothing about caches, files or object storage keyed by id.
- **`text()` checks are heuristic.** If a tenant table name appears in the SQL, the tenant column
  must appear too, and a bound `:tenant_id` must equal the bound tenant. The guard cannot
  rewrite `text()` or Core `Table` selects. In permissive mode they run unscoped and are
  reported with `corrected=False`.
- **Strict mode wants explicit predicates.** That is deliberate: it makes the scoping visible in
  review. The cost is that an id-only query on a tenant table needs either the predicate or a
  bypass.
- **Relationship loads are scoped, not checked.** Lazy and eager loads get the tenant criterion,
  but they never raise.
- **The matrix only knows what a `Resource` tells it.** It skips collection-level writes other
  than create, such as `POST /invoices/mark-paid`, because it cannot infer their body. Cover
  those with a hand-written test or the guard.
- **The Semgrep rules are syntactic and intra-procedural.** Each rule lists its tradeoffs.
- **Not a replacement for database-enforced isolation.** See [docs/design.md](docs/design.md)
  for the comparison with PostgreSQL row-level security. Where you can, use both.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" semgrep pre-commit && pre-commit install
ruff format --check . && ruff check . && mypy
coverage run -m pytest && coverage report      # fails under 95 %
semgrep --metrics=off --test semgrep/
python scripts/render_bug_table.py --check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Licensed under
[Apache-2.0](LICENSE).
