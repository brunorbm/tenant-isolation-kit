# Security policy

tenant-isolation-kit is a security control. If any of its layers misses a cross-tenant access
that it claims to catch, that is a vulnerability.

## Supported versions

While the project is pre-1.0, only the latest release receives fixes.

## Reporting a vulnerability

Report privately through GitHub's
[private vulnerability reporting](https://github.com/brunorbm/tenant-isolation-kit/security/advisories/new)
for `brunorbm/tenant-isolation-kit`. Do not open a public issue for a bypass.

A useful report contains:

- the smallest statement, handler or request sequence that reaches another tenant's rows
  without the layer noticing;
- the `TenantGuard` configuration or `Resource` description you used;
- your Python, SQLAlchemy, FastAPI and Semgrep versions;
- what the kit did, and what you expected it to do.

What to expect:

- an acknowledgement within 7 days;
- an assessment within 30 days;
- for confirmed issues, a fix and a GitHub security advisory, with credit if you want it.

Every confirmed bypass also becomes a regression test. A guard bypass goes in
`tests/test_guard.py`. A rule false negative becomes a `# ruleid:` case in `semgrep/`.

## In scope

- A statement that goes through a guarded `Session`, touches a tenant-scoped table, and
  returns or writes another tenant's rows:
  - in strict mode, without raising;
  - in permissive mode, without being scoped.
- A `before_flush` write that stores a row under another tenant without raising
  `CrossTenantWriteError`.
- A matrix case that passes even though tenant B reached tenant A's canary.

## Out of scope

- Everything listed under **Limitations** in the README, for example:
  - connections used outside a `Session`;
  - `text()` heuristics;
  - application caches;
  - collection-level bulk writes in the matrix.
- Semgrep false negatives that a rule already documents in `metadata.tradeoffs`.
  Improvements to those rules are still welcome as normal pull requests.
- Vulnerabilities in the deliberately vulnerable example app (`examples/vulnerable_app`).
