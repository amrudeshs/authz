# Philosophy — why the grants live in tables

## Route guards vs row filters

Policy engines usually evaluate rules in the application process: load the
policies, ask "may this subject do this action on this resource?", cache the
answer. That is a good fit for **route guards** — a handful of checks per
request against a small policy set.

It is a poor fit for **"list everything I may see."** To answer that in
memory you either fetch every candidate row into the process and filter
there, or you replicate the policy into a query and hope the two stay in sync.

This module is the route guard. Permission codenames and role bindings are
**tables**, so a host that needs a filtered list can join them in the same
query that scopes the tenant. This package does not ship that join, and it
does not evaluate row policies. A wildcard grant is not a row: a SQL join on
`role_permissions` alone would under-grant the admin relative to `Has`.
In-memory work is the per-request permission set — a small cached string-set
— never row filtering.

The trade-off is real: policy changes require a database write and an
invalidation, and the policy language for row filters is whatever SQL the
host writes. Keeping the two layers separate is what lets the function-level
check stay small.

## Fail closed

An authorization layer that fails open is worse than none, because it looks
like it is protecting something. The rules:

- Resolver errors propagate; the middleware maps them to **500**, never to a
  client deny. Unauthenticated is 401. A lookup error on a presented
  credential is 500, not an anonymous request.
- An empty permission set denies everything.
- Unknown codenames are inert (they match nothing) rather than wildcards.
- A corrupt cache entry is a **miss**, not an error — resolution re-runs.
- A cache `Get`/`Set`/`Del`/`Flush` error is a failure, not a miss and not a
  successful write.

## Wildcards instead of rows

A system-admin role is granted the whole vocabulary by **resolution**, not by
storing a row per capability. This means a new endpoint joins the vocabulary
and is immediately usable by admins without re-seeding every tenant — the
common failure mode where a new capability is invisible to the one role that
should always have it. The flag is recomputed on a cache hit from the
member's slugs and the current wildcard option, and the vocabulary snapshot
is refreshed, so the grant does not freeze at fill time.

The slug is a process option, not a column. Reserve it. A custom role with
that name is the admin, including on a tenant the seed never ran for.

## Cache partitioning

The key has to be one the invalidator can recompute. `tenant + user` is the
key `Invalidate` can drop; the example uses `perms:{tenantID}:{userID}`. A
session component defeats identity reuse (a test reset that restarts an ID
sequence cannot inherit a set), but then a membership change cannot find the
keys unless the host keeps an index of them or calls `Flush`. Do not document
a session key as the default and then invalidate a tenant+user key.

Invalidation is mandatory, and it has to be able to fail loudly:

- Role-definition changes affect every holder → `Flush`.
- Membership changes, including revocation, affect one member → `Invalidate`
  that member's key.
- An in-flight resolve in this process must not `Set` the pre-change snapshot
  after that. A generation checked at `Set` time is what this package does.
- Another instance can still `Set` a stale entry after `Flush`. **TTL bounds
  that race.** It is the backstop, not the freshness mechanism. A failed
  `Del` or `Flush` is returned; ignoring it is a stale gate.

## Migrations vs cached freshness

Vocabulary changes are code changes: regenerate from the spec, deploy, and
re-seed the system roles. Old codenames become inert orphans (fail closed)
until grants are updated — which is the safe direction. Wildcard holders do
not need that re-seed, and they do not need to wait out the TTL.

Role-definition edits are data changes: they must `Flush` cached sets. The
seed function is idempotent. A re-run replaces active system-role grants with
exactly the matrix; a slug removed from the matrix keeps its role row and
loses its grants. After the first call, inserting a tenant seeds that tenant
from the stored matrix, so new tenants are not invisible until someone
remembers.

## What this layer is not

Function-level authorization answers "may this member call this operation?" It
does not answer "which rows may they see?" or "may they act on this specific
object?" Those are **data-level** concerns — ownership, per-resource grants,
supervision hierarchies — that compose with this layer inside the handler.
Keeping the two separate is what lets the function-level layer stay small and
the data-level filters stay in SQL where they belong.
