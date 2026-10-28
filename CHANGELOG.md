# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-28

### Added

- `TenantGuard`, a runtime SQLAlchemy 2.x guard that hooks `do_orm_execute` and `before_flush`:
  - scopes ORM selects with `with_loader_criteria`, including aliases, joins and relationship
    loads;
  - scopes `update()` and `delete()` with an extra `WHERE`;
  - checks `text()` heuristically;
  - checks the tenant values of inserts, including `insert().values()` and executemany
    parameters;
  - **strict** mode raises on any statement without an explicit tenant predicate;
    **permissive** mode scopes the statement and reports it through `on_violation`.
- Tenant binding through `Session.info` or `tenant_scope()`, and `bypass_tenant_guard(reason)`,
  where the reason is mandatory.
- Cross-tenant test matrix, available as a `tenant_matrix` pytest marker and fixture. It
  generates read, write, list and forged-tenant cases (query, header, body) from the app's
  routes, uses canaries, and detects vacuous cases.
- Five Semgrep rules, each with `semgrep --test` fixtures and documented tradeoffs:
  - `tik-unscoped-pk-lookup`
  - `tik-path-param-lookup-without-ownership-check`
  - `tik-raw-sql-without-tenant-predicate`
  - `tik-bulk-write-without-tenant-filter`
  - `tik-tenant-id-from-request`
- `examples/vulnerable_app` with ten seeded bugs, `examples/fixed_app`, and a test suite that
  proves which layer catches each bug.

[Unreleased]: https://github.com/brunorbm/tenant-isolation-kit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/brunorbm/tenant-isolation-kit/releases/tag/v0.1.0
