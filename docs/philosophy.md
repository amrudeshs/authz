# Philosophy — why database-enforced authorization

## In-memory evaluation vs database filtering

Policy engines usually evaluate rules in the application process: load the
policies, ask "may this subject do this action on this resource?", cache the
answer. That is a good fit for **route guards** — a handful of checks per
request against a small policy set.

It is a poor fit for **"list everything I may see."** To answer that
in memory you either fetch every candidate row into the process and filter
there (moving data you will throw away), or you replicate the policy into a
query anyway and hope the two stay in sync.

This module keeps policies where the rows are. Permission codenames and role
bindings are **tables**, so the same `JOIN` that scopes a query to a tenant
also scopes it to what the caller may act on. In-memory evaluation is reserved
for the per-request permission set — a small cached string-set — never for row
filtering.

The trade-off is real: policy changes require a database write and an
invalidation, and the policy language is whatever SQL you can write rather
than a DSL. For multi-tenant services that already filter every query by
tenant, the direction is the same — and the filtering composes.

## Fail closed

An authorization layer that fails open is worse than none, because it looks
like it is protecting something. The rules:

- Resolver errors propagate; the middleware maps them to **500**, never allow.
- An empty permission set denies everything.
- Unknown codenames are inert (they match nothing) rather than wildcards.
- A corrupt cache entry is a **miss**, not an error — resolution re-runs.

## Wildcards instead of rows

A system-admin role is granted the whole vocabulary by **resolution**, not by
storing a row per capability. This means a new endpoint joins the vocabulary
and is immediately usable by admins without re-seeding every tenant — the
common failure mode where a new capability is invisible to the one role that
should always have it.

## Cache partitioning

Where a cached permission set lives determines whether it can leak:

- **session + tenant + user** is the recommended key. Sessions are random, so
  identity reuse (e.g. a test reset that restarts an ID sequence) cannot
  inherit a stale set; the tenant and user partitions keep multi-tenant
  members and target-user checks from reading the wrong set.
- **Invalidation is mandatory.** Role-definition changes affect every holder →
  flush everything. Membership changes affect one member → drop their key.
  A stale gate is a defect, not a TTL wait.

## Migrations vs cached freshness

Vocabulary changes are code changes: regenerate from the spec, deploy, and
re-seed the system roles. Old codenames become inert orphans (fail closed)
until grants are updated — which is the safe direction. Role-definition edits
are data changes: they must flush cached sets, and the seed function is
idempotent so it can be re-run after a truncation or a vocabulary change.

## What this layer is not

Function-level authorization answers "may this member call this operation?" It
does not answer "which rows may they see?" or "may they act on this specific
object?" Those are **data-level** concerns — ownership, per-resource grants,
supervision hierarchies — that compose with this layer inside the handler.
Keeping the two separate is what lets the function-level layer stay small and
the data-level filters stay in SQL where they belong.
