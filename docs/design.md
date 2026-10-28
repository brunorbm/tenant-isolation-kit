# Design

## Goal and non-goals

The kit narrows one bug class: a request authenticated as tenant B reads or changes rows that
belong to tenant A in a shared-schema database. It does not try to be an authorization
framework. The application still decides *who* may act. The kit makes sure that *which
tenant's rows* never depends on a line that someone can forget.

## Three layers, three moments

| | Semgrep rules | Test matrix | Runtime guard |
|---|---|---|---|
| Runs | on source, before merge | in the test suite | on every statement |
| Sees | code shapes | HTTP behaviour | SQL statements |
| Strength | cheap, points at the line | language-agnostic, sees caches and serializers | complete for what goes through a `Session` |
| Blind spot | indirection (`metadata.tables[...]`, helpers), non-PK keys | routes it cannot drive (bulk bodies), resources not described | anything outside the `Session`: caches, files, raw connections |
| Failure mode | false positives in review | vacuous cases (detected and reported) | false positives in strict mode (fixed by an explicit predicate) |

Each layer is placed where the previous one is weakest. That is the point of defense in depth:
the layers are uncorrelated, so a bug has to get past all three. The seeded-bug table in the
README shows this with real bugs:

- V7 gets past Semgrep, and the guard catches it.
- V8 gets past the guard, and the matrix catches it.
- V9 gets past Semgrep, and both other layers catch it.

## Layer 1: Semgrep rules

The rules are intra-procedural on purpose. They flag the four shapes that cause most
cross-tenant bugs in FastAPI + SQLAlchemy code:

- a primary-key lookup with no owner predicate;
- a path parameter flowing into a lookup inside a handler with no ownership check;
- raw SQL that names no tenant column;
- a bulk `update()`/`delete()` filtered only by id.

A fifth rule, written in taint mode, tracks a tenant id taken from the request (query, header,
body or path) into a query predicate or a model constructor.

Precision beats recall here. A rule that fires on every query gets disabled within a week.
Each rule records its known false positives and false negatives in `metadata.tradeoffs`. The
expected way to deal with a deliberate exception is a `# nosemgrep: <rule-id>` comment that
gives the reason. Examples of deliberate exceptions are a membership table or a policy engine
that authorizes outside the query.

## Layer 2: the cross-tenant matrix

Static rules cannot see behaviour. A response cache keyed by object id (V8) is correct code
line by line. The matrix therefore tests the running app. For each route under a described
collection, it derives cases:

| Kind | Route shape | Attack | Finding when |
|---|---|---|---|
| `read` | `GET` with a path parameter | B requests A's object | status not in `denied`, or A's canary in the body |
| `write` | `PUT`/`PATCH`/`POST`/`DELETE` with a path parameter | B writes to A's object | status not in `denied`, B's canary in A's object, or A's object gone |
| `list` | `GET` collection | B lists | A's canary in the body |
| `forge-query` / `forge-header` | `GET` collection | B names tenant A in a query parameter or header | A's canary in the body |
| `forge-body` | `POST` collection | B creates while naming tenant A | B's canary appears in A's list |

Design choices:

- **Canaries, not ids.** A finding means that A's random canary reached B, or that B's canary
  reached A. That catches leaks through any path: list, export, error message or cache.
  Matching on ids would miss most of these.
- **Vacuity check.** Before attacking, the matrix makes A perform the same read. If A cannot
  see its own canary, the case fails as `VacuousCaseError` instead of passing. A wrong
  `Resource` description therefore cannot turn into a green suite. The owner read also warms
  any cache, which is how V8 is found.
- **Fresh objects per case.** Each case creates its own resource, so cases are independent and
  can run in any order.
- **`denied` defaults to `{403, 404}`.** Returning 404 hides whether an object exists, and that
  is usually preferable. Returning 403 is accepted. A 200 with an empty body is not.

## Layer 3: the runtime guard

The guard hooks two `Session` events:

- `do_orm_execute` covers everything executed through the session. That includes `get()`,
  relationship loads, ORM and Core `update()`/`delete()`, and `text()`.
- `before_flush` covers unit-of-work writes.

For each statement, the guard:

1. **Fails closed.** If the statement touches a tenant-scoped table and no tenant is bound, it
   raises `MissingTenantContextError`.
2. **Checks the statement as written.** Each tenant table needs an explicit `tenant_id = :x` or
   `IN (...)` predicate at the top level of the `WHERE`, and the value must be the bound
   tenant. A missing predicate is reported as `UnscopedQueryError`. A predicate that names
   another tenant is reported as `CrossTenantQueryError`.
3. **Scopes the statement anyway.**
   - ORM selects get `with_loader_criteria`, in its lambda form, so that it is adapted to
     `aliased()` entities and follows joins and relationship loads.
   - `update()` and `delete()` get an extra `WHERE`.

**Strict mode** raises the step 2 error. Step 3 then only adds defense. The
guard asks for the explicit predicate even though it could add it silently, and the reason is
review: a query with a visible tenant predicate is correct on its own, without the guard.
Code also stays correct if it ever runs without the guard, for example in a script or a
migration.

**Permissive mode** reports through `on_violation` and relies on step 3. A forgotten
predicate, or a predicate forged to name another tenant, then becomes "no rows" instead of
"another tenant's rows". Use it to roll the guard out
to an existing codebase, then switch to strict mode.

**Writes** do not have a safe automatic fix. A new row without a tenant gets the bound tenant.
A row that names another tenant raises `CrossTenantWriteError` in both modes. Inserts executed
as statements, not through the unit of work, get the same check for executemany parameters
and `insert().values()`.

**Text SQL** is opaque to the guard. It applies a heuristic: if a tenant table name appears in
the SQL, the tenant column must appear too, and a bound `:tenant_id` must equal the bound
tenant. The guard cannot rewrite `text()`, so permissive mode reports it with
`corrected=False` and lets it run, which is the V4 row of the table.

**Bypass** is explicit. `bypass_tenant_guard(reason)` requires a reason and can be found with
grep. It is meant for cross-tenant jobs such as billing rollups or support tooling.

## Comparison with PostgreSQL row-level security

[Row-level security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) (RLS)
attaches a policy such as `USING (tenant_id = current_setting('app.tenant_id'))` to the table.
The database then enforces it for every query from a non-owner role.

| | PostgreSQL RLS | This kit's runtime guard |
|---|---|---|
| Enforced by | the database | the application process |
| Covers raw connections, other services, ad-hoc SQL | yes | no, only `Session` statements |
| Survives an application bug in the guard itself | yes | no |
| Database support | PostgreSQL | any SQLAlchemy backend (SQLite in the examples) |
| Failure signal | silently empty results (`USING`) or an error on writes (`WITH CHECK`) | a named exception that points at the statement, or an `on_violation` report |
| Code-review signal | none: queries look unscoped and are safe | explicit predicates in strict mode |
| Pitfalls | the table owner and `BYPASSRLS` roles skip policies unless `FORCE ROW LEVEL SECURITY` is set; the tenant setting must be reset on pooled connections; views and `SECURITY DEFINER` functions can bypass it | the `text()` heuristic; anything outside the session |
| Performance | the policy predicate is planned like any other predicate | statement inspection in Python on each execute |

RLS is the stronger boundary, and you should use it when you run PostgreSQL. The guard is
still useful next to it:

- **It fails loudly.** RLS turns a missing predicate into an empty result, which looks like
  correct behaviour. The guard turns it into an exception, with the statement attached, in the
  test suite.
- **It runs everywhere the tests run.** That includes SQLite test databases, which have no RLS.
- **It catches the same application bug that RLS would mask,** so the code base stays correct
  if RLS is misconfigured. Typical misconfigurations are a migration that runs as the owner,
  or a pooled connection that keeps the previous request's tenant setting.

Neither RLS nor the guard sees application caches or object storage. The matrix is the layer
that tests those.
