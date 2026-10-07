# Data-level authorization plan

**Status:** proposed — not implemented. Tracked to be picked up in a future
session, alongside `docs/redis-support-plan.md` and `docs/testing-plan.md`.

## Goal

Decide how this repository should cover **data-level** authorization —
ownership, per-resource grants, and supervision hierarchies — given that the
core deliberately answers only *"may this member call this operation?"*.

This document records what a working reference implementation does (Edoola,
`../edoola-go`), what would and would not fit here, and the options. It does
not propose moving row filtering into the dependency-free core.

## Where the code is today

- The core (`authz.go`) and the chi adapter are **function-level only**. Row
  filters stay in the host's SQL (`docs/philosophy.md`, "What this layer is
  not").
- The reference schema (`schema/001_authz.sql`) models roles and bindings, not
  ownership or grants.
- The example scopes by tenant (`WHERE tenant_id = $1`) and never compares
  `owner_id` to the caller.
- `README.md` lists "data-level layers" as an explicit non-goal.

So "data-level" is currently a documented boundary, not code.

## The reference implementation: `../edoola-go` (ADR-0010 layers b–d)

Edoola built the data layer **on top of** this module (its `internal/authz` is
an earlier copy of the same core). Its own design record lists data-level
authorization under "What stays host-side (deliberately NOT in the core)"
(`docs/authz/README.md`) and as an open-source non-goal. The pieces:

| Layer | Schema | Rule |
|---|---|---|
| **(b) Ownership** | `owner_id` on the content tables, read as `COALESCE(owner_id, created_by)`; transferable | write is owner-only |
| **(c) Explicit grants** | `content_grants (id, tenant_id, subject_user_id?, subject_group_id?, object_type, object_id, action read\|edit, created_by, revoked_at)`; partial-unique live grant; soft-revoke | share read (default) or edit with a user or group |
| **(d) Supervision hierarchy** | `org_nodes` (adjacency list) + `org_members` (one node per user) | read flows **down** the subtree; peers strict-deny |
| (adjacent) Invite allowlist | `tenant_domains` | admin-managed email-domain rule; empty ⇒ unrestricted |

The policy shape is a table-driven tuple
`(subject, action, object-type, object-id?, conditions)`, deliberately short
of ReBAC.

**Enforcement architecture** (`internal/apiimpl/authz.go`):

- Resolve **once per request, cached**:
  - `visibleOwnerIDs` = `{me} ∪ subtree(me)` via a recursive CTE
    (`ListVisibleOwnerIDs` in `queries/org_scope.sql`); `(nil, unrestricted)`
    for the `admin` wildcard slug. Cached as `owners:ses:{token}:{tenant}:{user}`, TTL 10m.
  - `grantScopeOf` = live grants for the user plus their groups, split into
    per-`object_type` read/edit id arrays (`ListGrantSubjectObjects`).
- Derive predicate arrays: `readFilter` → `(visible_owner_ids, read_grant_ids)`;
  `writeFilter` → `({me}, edit_grant_ids)`; admin → `(nil, nil)`.
- **Inject the predicate into every list/get query** (`queries/authoring.sql`),
  e.g.:
  ```sql
  AND (sqlc.narg(visible_owner_ids)::bigint[] IS NULL
       OR COALESCE(owner_id, created_by) = ANY(sqlc.narg(visible_owner_ids)::bigint[])
       OR id = ANY(sqlc.narg(read_grant_ids)::bigint[]))
  ```
  `NULL` = admin skip. The plan calls this **"no post-fetch filtering"** — the
  DB never returns a row the caller cannot see.
- Grants CRUD gates on an *edit* guard first (`authorizeObjectEdit`, owner or
  live edit grant or admin), then mutates (`internal/apiimpl/grants.go`).
- Invalidation: org/grant/ownership mutations sweep the derived caches
  (`flushOwnerScopeCaches`), via `DeleteMatching("owners:*")` on the concrete
  Redis cache.

Reference files (in `../edoola-go`): `migrations/000051_data_authorization_schema.up.sql`,
`queries/grants.sql`, `queries/ownership.sql`, `queries/org_scope.sql`,
`internal/apiimpl/authz.go`, `internal/apiimpl/grants.go`,
`internal/apiimpl/ownership.go`, `docs/spec/data-authorization-plan.md`.

## Feasibility here

Possible, but **not in the dependency-free core** — it needs DB I/O and
per-object-type SQL. Three shapes, cheapest first:

- **A. Reference-only (recommended first step).** A schema sketch + how the
  layers compose, kept as documentation. Matches the current philosophy at no
  API cost.
- **B. Optional sibling package.** A storage-agnostic package (e.g.
  `dataauthz`) with interfaces analogous to `Resolver` —
  `VisibleOwnerIDs(ctx, tenant, user)` and `GrantScope(ctx, tenant, user)` —
  the host supplying the SQL, plus a reference Postgres implementation in
  `example/`. The core stays I/O-free because this is a separate package.
- **C. Full example port.** Extend `example/` with `owner_id`,
  `content_grants`, `org_nodes`, and rewrite its list/get queries with the
  predicates, as a runnable showcase.

## Constraints and risks

- **No post-fetch filtering** means every host list/get query must embed the
  predicate — a host-wide change, which is why it stays host-side.
- **Generic-izing is awkward.** `object_id` is polymorphic and each object
  type needs its own guard query; Edoola's code is sqlc-generated against its
  own four content types. It is a pattern to port, not code to copy.
- **A new cache family** (owner/grant sets) with its own keys and flush. The
  flush is the namespaced-`Flush`/`DeleteMatching` gap tracked in
  `docs/redis-support-plan.md`; that gap is a prerequisite.
- **Error policy must be chosen.** Edoola's older cache contract has no error
  returns, so a Redis outage is a miss and resolution falls back to the DB
  (degrade). This repo's current contract is fail-closed (cache error → 500).
  Decide which the data-level caches follow.
- **Effort.** Edoola shipped it in slices 15a–15f (stages 81–90): schema, read
  predicates, write predicates + grants CRUD, org tree + invites + domains,
  ownership transfer, UI/e2e.

## Work breakdown

- [ ] Decide the shape (A reference-only, B sibling package, C example port).
- [ ] If adopting: update `README.md` and `docs/philosophy.md` to describe
      data-level authorization as a host composition rather than a flat
      non-goal.
- [ ] Draft the reference schema (`owner_id`, `content_grants`,
      `org_nodes`/`org_members`) as illustrative DDL, not core.
- [ ] Define the predicate-injection pattern and the admin-wildcard `NULL`
      convention.
- [ ] Define the derived-cache keys and their invalidation, coordinated with
      `docs/redis-support-plan.md`.
- [ ] Add contract tests (peer-deny, read-down, grant allow/deny/revoke,
      admin wildcard, cross-tenant isolation) per `docs/testing-plan.md`.

## Open questions

- Document only, an optional `dataauthz` package, or a full example port?
- Should the core expose a typed `PermissionSet.RoleSlugs`-style hook for the
  admin wildcard the data layer reuses (Edoola checks the `admin` slug
  directly)?
- Does the data layer get its own cache abstraction, or reuse `authz.Cache`
  with a key namespace?
- Fail-closed or degrade-to-resolver for the derived caches?

## Non-goals

- Moving row filtering into `authz.go`; the core stays dependency-free and
  I/O-free.
- PostgreSQL row-level security (pooled-connection `SET LOCAL` hazards;
  application-level scoping composes instead).
- ReBAC / a policy DSL; the tuple stays short of that.
