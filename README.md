# authz — multi-tenant, database-enforced RBAC for Go

A small, dependency-free authorization core for multi-tenant Go services:
permission **codenames** form a static vocabulary, **roles** are per-tenant
rows bundling codenames, and **memberships** hold roles. Authorization is a
per-request set-membership check over a resolved `PermissionSet`.

The design motivation is the table-driven route: **policies live in
PostgreSQL and the database filters natively**, composing with tenant scoping
as ordinary SQL — rather than evaluating every policy in memory (the Casbin
trade-off) and pulling rows into the service only to discard them.

This repository ships:

- the core module (this package) — stdlib-only;
- a generic reference schema + an idempotent role-seed function;
- `cmd/permgen`, which derives the vocabulary, route→codename map and role
  seed from any bundled OpenAPI document;
- an optional `chi/` middleware adapter and an in-memory `cache/`;
- a runnable multi-tenant **Projects & Tasks** example;
- docs (design, quickstart, philosophy).

See `docs/` for the quickstart and the design rationale.

## License

Apache-2.0. See `LICENSE`.
