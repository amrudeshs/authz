# authz — multi-tenant function-level RBAC for Go

A small, dependency-free authorization core for multi-tenant Go services.
Permission **codenames** form a static vocabulary; **roles** are per-tenant
rows bundling codenames; members hold roles through their membership.
Authorization is a per-request set-membership check over a resolved
`PermissionSet`, cached with an explicit invalidation contract.

This layer answers "may this member call this operation?" It does not answer
"which rows may they see?" Grants live in PostgreSQL so a host *can* join
them into a list query, next to the tenant predicate. That join is the
host's SQL. This module does not evaluate it, and a wildcard grant is not a
row — a join on `role_permissions` alone would under-grant the admin relative
to `Has`.

## Why

Go has no standard permission model (the kind a batteries-included web
framework auto-generates: per-object `add/change/delete/view` permissions,
bundled into groups, resolved per user). The common Go answer evaluates
policies **in memory**. That is a good fit for a route guard. It is a poor
fit for "list everything I may see" if the service pulls every candidate row
into the process only to discard most of them.

This module keeps the route guard small and the grants in tables. If a list
must be capability-filtered, write that filter in SQL. Do not look for it
here: row-level security and data-level authorization are non-goals. In-memory
work is the per-request permission set — a small cached string-set — never
row filtering.

## Design in one paragraph

Permission **codenames** form a static vocabulary (generate them from an
OpenAPI document, one per operation, or any source you like). **Roles** are
per-tenant rows bundling codenames. **Members** hold roles. Authorization =
resolve the member's role slugs + codename union, cache under a key the
invalidator can recompute, then a set-membership check per request. A
wildcard option lets a system-admin role grant the whole vocabulary without
stored rows. Storage and cache are **interfaces the host implements** — the
core owns no I/O.

## The core package — dependency-free

| Symbol | Role |
|---|---|
| `PermissionSet` | Resolved state: role slugs + codename union + wildcard flag. `Has`, `HasRole`, `All`. |
| `Resolver` (interface) | Host storage: `RoleSlugs(ctx, tenantID, userID)` and `PermissionCodenames(ctx, tenantID, slugs)`. Implementations must scope every query to `tenantID`. The core cannot check that. |
| `Options{WildcardRoleSlug}` | Members holding this slug pass every check. Empty disables wildcarding. Reserve the slug; do not let `CreateRole` mint it. |
| `Resolve(...)` | Pure resolution: slugs → (wildcard ? full vocabulary : codename union). |
| `Cache` (interface) | `Get/Set/Del/Flush` over opaque bytes. Mutations return errors. Wire to Redis, an LRU, or nothing — see `docs/redis-support-plan.md` for the Redis path. |
| `CachedResolver` | Decorator with `ResolveFor`, `Resolve`, `Invalidate`, `Flush`. |

Rules:

- **Fail closed** — resolver and cache errors propagate. The chi middleware
  maps them to **500**, never to a client deny. `ErrUnauthenticated` is 401.
- **Unknown routes deny by default** — inside the group the middleware is
  installed on. It gates every matched route from an explicit policy map;
  public routes come from a separate explicit allowlist. A route missing
  from both is a misconfiguration (500). A route registered outside the
  group never reaches the middleware. An unmatched path is the router's 404.
- **Empty role slugs deny every codename.** That is not "no membership."
  The host answers membership separately so it can return 404 (existence
  hiding) instead of 403.
- **Wildcard grants everything**, including codenames invented after the
  resolve. The flag survives the cache: a hit recomputes it from the
  member's slugs and refreshes the vocabulary snapshot. A system admin does
  not need re-seeding when the vocabulary grows.
- **Cache keys must be recomputable by the invalidator.** The key `Invalidate`
  can drop is `tenant + user` (the example uses `perms:{tenantID}:{userID}`).
  A session component defeats identity reuse, but then a membership change
  cannot find the keys unless the host keeps an index or calls `Flush`.
  Role-definition edits call `Flush`. A failed `Del` or `Flush` is returned,
  not ignored. TTL bounds a cross-instance race where another process `Set`s
  a stale entry after `Flush`; it is the backstop for that race, not the
  freshness mechanism.

## Data model

`schema/001_authz.sql` ships a generic reference schema:

```sql
roles (id, tenant_id, slug, name, is_system, deleted_at, ...)
role_permissions (role_id, permission_codename)
membership_roles (membership_id, role_id, tenant_id)
```

Semantics that make the model robust:

- **Memberships, not users.** Roles bind to the membership (the user×tenant
  row). `membership_roles.tenant_id` must match both the membership and the
  role, so a binding cannot point at another tenant's role. The reference
  resolver also filters `r.tenant_id = m.tenant_id`. Slug equality is what
  the wildcard checks; without the constraint a foreign `owner` slug would
  grant the caller's whole vocabulary.
- **System-role grants are owned by the seed function.** `is_system` marks
  the row. A trigger rejects permission changes, and updates or deletes of
  the role row, unless `seed_role_permissions` is running. The example also
  refuses in the handler and writes `AND is_system = false`. Do not treat a
  0-row update as success. A role that can `SET authz.seeding` can bypass
  the trigger; application code should call the function instead.
- **Soft delete** is a column the host must both write and filter. The
  reference resolver filters `deleted_at`. The core cannot see a query that
  forgets to.
- **Wildcards instead of rows** for the admin role: a new endpoint is
  immediately admin-usable, including on a cache hit, without re-seeding
  every tenant. Put the slug in the seed matrix with an empty array so the
  row exists, and set `WildcardRoleSlug` to that slug. Reserve the slug so
  a custom role cannot take it on an unseeded tenant.
- **Unknown codenames fail closed**: an orphan row matches nothing unless a
  route asks for that exact string. Codegen does not sweep the table.

`schema/002_seed_function.sql` ships `seed_role_permissions(jsonb)` — an
idempotent, re-invocable system-role matrix seed. A re-run replaces the
grants of every active system role with exactly the matrix; slugs dropped
from the payload keep their role row and lose their grants. The matrix is
stored, and a trigger seeds a newly inserted tenant from it, touching only
that tenant's rows; tenants created before the first seed are brought in
line when the host calls the function. Include the wildcard role
with an empty array so its row exists for membership binding. `x-role-seed`
is that matrix, including the wildcard slug — the example checks
`seed.sql` against the generated `RoleSeed`.

## Vocabulary generation (`cmd/permgen`)

If the host is OpenAPI-first, generate the vocabulary from the spec in the
same pipeline as the server codegen — one codename per `operationId`, plus
non-endpoint capabilities declared as `x-permissions` on the root document,
plus a `METHOD /path` → codename map for middleware enforcement and an
explicit `PublicRoutes` allowlist. Mark public operations `x-public: true`:
they stay in the vocabulary and land in `PublicRoutes`, not in the codename
map — so the middleware can distinguish a declared public route from an
unmapped (misconfigured) one. The optional root `x-role-seed` declares the
default role matrix.

```sh
go run ./cmd/permgen -spec example/openapi.json -out example/perm_gen.go -package main
```

## Enforcement pattern (middleware-first)

Capability checks live in **middleware, before the handler**, using the
route→codename map; the handler performs only data-level checks (ownership,
workspace scoping). Those checks are the host's SQL. Recommended denial
semantics, which the chi adapter implements:

| Condition | Response |
|---|---|
| No session on a gated route | 401 |
| Credential or workspace lookup failed | 500 — not an anonymous request |
| No active membership on the tenant | 404 (existence hiding) |
| Membership without the codename | 403 |
| Resolution, membership-check, or cache invalidation failure | 500 — fail closed |
| Matched route inside the group, absent from both maps | 500 — misconfiguration, fail closed |

Cache invalidation is part of the contract: role-definition changes call
`Flush` (every holder); membership changes, including revocation, call
`Invalidate` on that member's recomputable key. A failed flush or delete is
a 500, not a success with a stale gate.

## Repository layout

| Path | What it is |
|---|---|
| `authz.go` | The dependency-free core. |
| `schema/` | Reference DDL + the idempotent seed function. |
| `cmd/permgen` | OpenAPI → vocabulary / route map / role seed generator. |
| `chi/` | The chi router adapter (the core stays framework-free). |
| `cache/` | An in-memory `authz.Cache` (Redis is the host's choice for multi-instance). |
| `example/` | A runnable multi-tenant "Projects & Tasks" service. |
| `docs/redis-support-plan.md` | Proposed plan for a Redis-backed shared cache (not implemented yet). |

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
`docs/philosophy.md` for why the grants are tables and the check is not a
row filter.

## Tests

`go test ./...` runs the unit suite. The Postgres tests in
`example/pg_integration_test.go` skip unless `DATABASE_URL` is set.
`REQUIRE_POSTGRES=1` fails the run instead of skipping. CI does that against
Postgres 18.

Those tests are what lock the contracts the in-memory suite cannot represent:
a cross-tenant role binding is rejected, system-role grants change only
through `seed_role_permissions`, a re-seed drops grants for a removed slug, a
tenant created after the seed receives the stored matrix, and the example
HTTP gate behaves the same on Postgres as it does in memory.

```sh
docker network create authz-test
docker run -d --name authz-pg --network authz-test \
  -e POSTGRES_PASSWORD=authz postgres:18-alpine
docker run --rm --network authz-test -v "$PWD":/src -w /src \
  -e DATABASE_URL=postgres://postgres:authz@authz-pg:5432/postgres \
  -e REQUIRE_POSTGRES=1 \
  golang:1.25-alpine go test ./...
docker rm -f authz-pg
docker network rm authz-test
```

The test process retries the database for 30 seconds, so Postgres does not
have to be ready before `go test` starts.

## License

Apache-2.0. See `LICENSE`.
