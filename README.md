# authz — multi-tenant, database-enforced RBAC for Go

A small, dependency-free authorization core for multi-tenant Go services.
Permission **codenames** form a static vocabulary; **roles** are per-tenant
rows bundling codenames; members hold roles through their membership.
Authorization is a per-request set-membership check over a resolved
`PermissionSet`, cached with an explicit invalidation contract.

The design motivation is the table-driven route: **policies live in
PostgreSQL and the database filters natively**, composing with tenant scoping
as ordinary SQL — rather than evaluating every policy in memory and pulling
rows into the service only to discard most of them.

## Why

Go has no standard permission model (the kind a batteries-included web
framework auto-generates: per-object `add/change/delete/view` permissions,
bundled into groups, resolved per user). The common Go answer evaluates
policies **in memory** — fine for route guards, but not for "list everything
I may see": at scale you fetch thousands of rows just to discard most of them.

This module takes the table-driven route. In-memory evaluation is reserved
for the per-request permission set (a small cached string-set), never for row
filtering.

## Design in one paragraph

Permission **codenames** form a static vocabulary (generate them from an
OpenAPI document, one per operation, or any source you like). **Roles** are
per-tenant rows bundling codenames. **Members** hold roles. Authorization =
resolve the member's role slugs + codename union, cache per session with an
invalidation hook, then a set-membership check per request. A wildcard option
lets a system-admin role grant the whole vocabulary without stored rows.
Storage and cache are **interfaces the host implements** — the core owns no
I/O.

## The core package — dependency-free

| Symbol | Role |
|---|---|
| `PermissionSet` | Resolved state: role slugs + codename union + wildcard flag. `Has`, `HasRole`, `All`. |
| `Resolver` (interface) | Host storage: `RoleSlugs(ctx, tenantID, userID)` and `PermissionCodenames(ctx, tenantID, slugs)`. Implementations MUST be tenant-scoped by construction. |
| `Options{WildcardRoleSlug}` | Members holding this slug pass every check. Empty disables wildcarding. |
| `Resolve(...)` | Pure resolution: slugs → (wildcard ? full vocabulary : codename union). |
| `Cache` (interface) | `Get/Set/Del` over opaque bytes — wire to Redis, an LRU, or nothing. |
| `CachedResolver` | Decorator with `ResolveFor(ctx, cacheKey, tenantID, userID)`, `Resolve`, `Invalidate`. |

Rules the core enforces by construction:

- **Fail closed** — resolver errors propagate; the documented middleware maps
  them to deny, never open.
- **Empty role slugs mean "no active membership"** — hosts distinguish "member
  with no roles" (403 on gated routes) from "no membership" (404, existence
  hiding). Both resolve to a deny; the host chooses the status code.
- **Wildcard grants everything**, including codenames invented after the
  resolve — a system admin never needs re-seeding when the vocabulary grows.
- **Cache keys are the host's choice.** The recommended granularity is
  `session + tenant + user`: random tokens defeat identity reuse, the tenant
  partition keeps multi-tenant members safe, and the user partition keeps
  target-user checks from reading the caller's set.

## Data model

`schema/001_authz.sql` ships a generic reference schema:

```sql
roles (id, tenant_id, slug, name, is_system, deleted_at, ...)
role_permissions (role_id, permission_codename)
membership_roles (membership_id, role_id)
```

Semantics that make the model robust:

- **Memberships, not users.** Roles bind to the membership (the user×tenant
  row), which is tenant-scoped for free and meaningless outside a tenant.
- **System roles are immutable by construction**: `is_system = true` plus the
  guard `AND is_system = false` on writes. Refuse in the handler too — never
  rely on a silent 0-row no-op.
- **Soft delete** on roles; soft-deleted roles grant nothing.
- **Wildcards instead of rows** for the admin role: a new endpoint is
  automatically admin-usable without re-seeding every tenant.
- **Unknown codenames fail closed**: orphan rows match nothing.

`schema/002_seed_function.sql` ships `seed_role_permissions(jsonb)` — an
idempotent, re-invocable system-role matrix seed. Include the wildcard role
with an empty array so its row exists for membership binding.

## Vocabulary generation (`cmd/permgen`)

If the host is OpenAPI-first, generate the vocabulary from the spec in the
same pipeline as the server codegen — one codename per `operationId`, plus
non-endpoint capabilities declared as `x-permissions` on the root document,
plus a `METHOD /path` → codename map for middleware enforcement. Mark public
operations `x-public: true` (they stay in the vocabulary but are absent from
the middleware map). The optional root `x-role-seed` declares the default
role matrix.

```sh
go run ./cmd/permgen -spec example/openapi.json -out example/perm_gen.go -package main
```

## Enforcement pattern (middleware-first)

Capability checks live in **middleware, before the handler**, using the
route→codename map; the handler performs only data-level checks (ownership,
workspace scoping). Recommended denial semantics:

| Condition | Response |
|---|---|
| No session on a gated route | 401 |
| No active membership on the tenant | 404 (existence hiding) |
| Membership without the codename | 403 |
| Resolution failure | 500 — fail closed |

Cache invalidation is part of the contract: role-definition changes flush all
cached sets (they affect every holder); membership changes flush that
member's keys.

## Repository layout

| Path | What it is |
|---|---|
| `authz.go` | The dependency-free core. |
| `schema/` | Reference DDL + the idempotent seed function. |
| `cmd/permgen` | OpenAPI → vocabulary / route map / role seed generator. |
| `chi/` | The chi router adapter (the core stays framework-free). |
| `cache/` | An in-memory `authz.Cache` (Redis is the host's choice for multi-instance). |
| `example/` | A runnable multi-tenant "Projects & Tasks" service. |

## What stays host-side

Storage (behind `Resolver`), vocabulary tooling, cache implementation, the
DDL/migrations, data-level authorization (ownership, per-resource grants,
hierarchies), and audit logging.

## Non-goals

Row-level security inside PostgreSQL, data-level layers, audit-log storage,
and identity/session management.

## Example

```sh
cd example
docker compose up --build
curl -s localhost:8080/health
```

See `docs/quickstart.md` for the full allow/deny walkthrough, and
`docs/philosophy.md` for the in-memory-vs-database trade-off.

## License

Apache-2.0. See `LICENSE`.
