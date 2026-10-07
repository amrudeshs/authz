# Testing plan

**Status:** proposed — not implemented. Tracked to be picked up in a future
session, alongside `docs/redis-support-plan.md`.

## Goal

Make the suite a contract, not just a collection of unit tests:

- every implementation of an exported interface runs a shared conformance
  suite, so a new store or cache is correct by construction;
- generated code has a golden test in addition to the CI drift check;
- CI runs the race detector.

The rule, stated once: **each exported interface ships a conformance suite,
each implementation registers with it, and CI runs `go test -race ./...`.**

## Where the code is today

| File | Tests | Kind |
|---|---|---|
| `authz_test.go` | 16 | Unit — core against doubles (`stubResolver`, `mapCache`, `errCache`, `blockingResolver`) |
| `cache/memory_test.go` | 5 | Unit — `cache.Memory` directly |
| `chi/middleware_test.go` | 3 | Unit — adapter against `stubResolver`/`slugResolver` |
| `cmd/permgen/main_test.go` | 4 | Unit — generator against a string fixture |
| `example/server_test.go` | 9 | Integration (in-process) — full router + middleware over `memStore` |
| `example/pg_integration_test.go` | 5 | Integration (Postgres) — schema, triggers, resolver, HTTP gate |
| `example/seed_sync_test.go` | 1 | Cross-artifact — `RoleSeed` vs `seed.sql` |

Already contract-shaped, but not reusable:

- Compile-time interface assertion `var _ authz.Cache = (*Memory)(nil)`
  (`cache/memory.go`). Proves satisfaction, not behavior.
- The chi decision table (401/404/403/500 ordering) is pinned by
  `chi/middleware_test.go`, but only for the in-file stub.
- `example/pg_integration_test.go` asserts real storage/schema invariants, but
  they are Postgres-specific rather than a shared suite.

## Gaps

1. **No conformance suite for `authz.Cache`.** `cache.Memory` is tested
   directly. A new implementation (Redis) has nothing reusable to run — the
   first instance of this gap, tracked in `docs/redis-support-plan.md`.
2. **No conformance suite for `authz.Resolver`.** `pgStore` is exercised by
   `pg_integration_test.go`; `memStore` only indirectly via `server_test.go`.
   The two are tested to different depths, and a third resolver has no shared
   suite.
3. **No reusable contract for `chi.Resolver`.** A host's resolver is only
   covered by whatever their own tests do; the adapter's decision table is not
   runnable against it.
4. **No golden test for `permgen`.** The committed `example/perm_gen.go` is
   protected only by CI's `git diff --exit-code`; a local regression is only
   caught after regeneration.
5. **CI does not run `-race`** (`.github/workflows/ci.yml` runs plain
   `go test ./...`), despite concurrency-sensitive code: `cache.Memory`'s
   mutex, the `atomic.Uint64` generation in `CachedResolver`, and the
   in-flight-invalidation test (`blockingResolver`).
6. **Interface-satisfaction assertions are ad hoc.** Only `authz.Cache` has a
   `var _` assertion; `authz.Resolver`, `chi.Resolver`, and the example's
   `Store` do not.

## Proposed design

### 1. `cache/cachetest` — the `authz.Cache` conformance suite

`cache/cachetest.Suite(t *testing.T, newCache func() authz.Cache)` asserting the
contract:

- a missing key is `ok=false, err=nil`;
- `Set` then `Get` round-trips the bytes;
- `ttl <= 0` never expires; a positive TTL expires;
- `Del` removes a key and is a no-op on a missing key;
- `Flush` drops every entry, including non-expiring ones;
- `Get` returns bytes independent of a later `Set` of the same key;
- a failing implementation surfaces errors, not silent success.

`cache.Memory` and the future Redis implementation both register.

### 2. `resolvertest` — the `authz.Resolver` conformance suite

`resolvertest.Suite(t, newStore func(t) (authz.Resolver, Fixture))`, where the
fixture supplies tenant/user ids and the expected slugs/grants. Assert:

- a member's slugs and codename union are returned for the given tenant;
- a user with no membership yields no slugs, no error;
- another tenant's roles are never returned (tenant scoping);
- soft-deleted roles grant nothing and are not returned;
- unknown codenames are returned verbatim and match nothing (no vocabulary
  filtering);
- `PermissionCodenames` unions across the requested slugs.

`memStore` and `pgStore` both register; the Postgres run stays behind
`DATABASE_URL`/`REQUIRE_POSTGRES`.

### 3. `chi` resolver contract

Extract the decision table into a helper hosts can run against their own
`chi.Resolver` (a `chi/chitest` package, or a documented `contract_test.go`
pattern): gated route allows only with the codename; 401 for unauthenticated;
404 for no membership; 500 for a resolver error and for an unmapped route
(even for a wildcard).

### 4. `permgen` golden test

Add `cmd/permgen/testdata/*.json` inputs and matching `.golden.go` outputs,
compared byte-for-byte, with a `-update` flag to regenerate. Keep the CI drift
check; the golden test catches regressions without running the generator by
hand.

### 5. CI hardening

- Run `go test -race ./...` in the `test` job (it already has the Postgres
  service and `DATABASE_URL`/`REQUIRE_POSTGRES`). If runtime is a concern, a
  separate `race` job that omits the integration env.
- Add a `REDIS_URL`/`REQUIRE_REDIS` gated run when the Redis implementation
  lands (see the Redis plan).

### 6. Compile-time assertions

Add `var _ authz.Resolver = (*pgStore)(nil)`, `var _ authz.Resolver =
(*memStore)(nil)`, `var _ chi.Resolver = (*server)(nil)`, and the equivalent
for `Store`, so an interface drift is a build failure.

## Work breakdown

- [ ] Add `cache/cachetest` and register `cache.Memory`.
- [ ] Add `resolvertest` and register `memStore` + `pgStore`.
- [ ] Extract the chi decision table into a reusable contract.
- [ ] Add the `permgen` golden test with `-update`.
- [ ] Add the compile-time interface assertions.
- [ ] Run `-race` in CI.
- [ ] Update `README.md` (`## Tests`) and this doc.

## Open questions

- Where do conformance packages live: `cache/cachetest` and a top-level
  `resolvertest`, or one `internal/…` test-support package?
- How much fixture surface does a generic `authz.Resolver` suite need before
  it becomes more complex than the cut-down per-store tests?
- `-race` in the main job (slower) or a separate job (clearer signal)?
- Do golden files belong in-repo, or is the CI drift check enough for
  `permgen`?

## Non-goals

- A code-coverage percentage target.
- Fuzzing or property-based testing (worth revisiting, not now).
- Replacing the Postgres integration tests with the conformance suite — the
  suite covers the interface; the integration test still owns schema,
  triggers, and the HTTP gate.
