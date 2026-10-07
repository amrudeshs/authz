# Redis support plan

**Status:** proposed — not implemented. Tracked to be picked up in a future
session.

## Goal

Let a host back `authz.Cache` with Redis (or any shared store) instead of
`cache.Memory`, without changing the core or the chi adapter, and get correct
invalidation across multiple service instances.

## Where the code is today

`authz.Cache` (`authz.go`) is already shaped for a remote implementation:

- `Get(ctx) ([]byte, bool, error)`, `Set(ctx, key, val, ttl) error`,
  `Del(ctx) error`, `Flush(ctx) error` — context, TTL, and failures are all
  part of the contract.
- `CachedResolver` calls the interface directly (no concrete type assert) and
  returns cache errors; the example maps them to 500.
- Values are opaque bytes; serialization stays in `CachedResolver` (JSON), so
  the cache layer stays dumb.
- `PermissionSet` marshals the wildcard flag and `restore` recomputes it on a
  hit, so a wildcard set survives a Redis round-trip and a vocabulary change.

That is enough to write a Redis implementation. It is not yet enough to run
one safely in production.

## Gaps

1. **No implementation ships.** `cache/` contains only `memory.go` and
   `memory_test.go`.
2. **`Flush` has no namespace.** The signature gives an implementation no way
   to know which keys belong to authz. A Redis implementation must hardcode a
   prefix and then either `SCAN`+`UNLINK` (O(N), potentially slow) or
   `FLUSHDB` (destroys unrelated keys on a shared Redis). `Flush` runs on
   every role-definition edit.
3. **Cross-instance invalidation is TTL-only.** The generation guard in
   `CachedResolver` is a process-local `atomic.Uint64`. A `Del`/`Flush` on one
   instance does not stop another instance's in-flight resolve from
   re-`Set`ing a stale value, and other instances keep serving stale until
   TTL. This is documented as a limitation, but with a shared cache the
   expectation is prompt invalidation.
4. **Fail-closed makes Redis a hard hot-path dependency.** A `Get` error is a
   500; a `Set` error is a 500 even though resolution succeeded. A Redis blip
   takes down every gated route while the resolver/DB is available.
5. **No stampede control.** A cold or just-flushed cache sends every
   concurrent request for the same key to the resolver.
6. **No lifecycle, conformance tests, or integration coverage.** No
   `Close`/`Ping`; no shared cache test suite; no Redis test wired into CI.

## Proposed design

### 1. Namespace the cache

Add a key prefix to the cache path, for example a `KeyPrefix string` field on
`CachedResolver` that the host's `Key` function incorporates, plus a helper the
Redis implementation uses for `SCAN`/`UNLINK`. Define `Flush` as "drop every
key under the prefix" — never `FLUSHDB`. Physical cleanup is best-effort;
correctness should not depend on it (see the epoch below).

### 2. Shared generation (epoch) for prompt invalidation

Make role-definition invalidation O(1) and cross-instance:

- Keep an epoch key, for example `authz:epoch`, incremented by `Flush`.
- Include the epoch in the cache key: `perms:{epoch}:{tenant}:{user}`.
- On `Flush`, `INCR authz:epoch`. Old entries become unreachable and age out
  by TTL. No scan is required for correctness.
- On a hit, the epoch used must be the current one. The host may cache the
  epoch in-process for a short TTL to avoid a Redis round-trip per request;
  that reintroduces a staleness window bounded by the epoch TTL.
- `Invalidate` (a membership change) needs the current epoch to compute the
  key, then `Del`.

This is the change that makes a shared cache actually prompt across instances;
the prefix cleanup in (1) only reclaims memory.

### 3. Decide the error policy

Keep fail-closed as the default (security first), but make the availability
trade-off explicit and configurable, via a field on `CachedResolver` (no
interface change):

- **Fail-closed** (current): a cache error is a 500.
- **Fallback**: on a `Get` error, `Resolve` from the resolver and skip `Set`;
  only 500 if the resolver also fails.

Document the security implications of each.

### 4. Stampede protection

Add per-key singleflight around `Resolve` in `ResolveFor` so concurrent misses
collapse to one resolver call. `golang.org/x/sync` (including `singleflight`)
is already an indirect module dependency.

### 5. Lifecycle

Do not put `Close`/`Ping` on `authz.Cache` — the core stays minimal. Expose
them on the Redis implementation; the host owns the client, health checks,
TLS/auth, and readiness. Document the expected wiring.

### 6. Tests

- `cache/cachetest`: a reusable conformance suite,
  `Suite(t, newCache func() authz.Cache)`. Assert: a miss is `ok=false, nil`;
  `Set`/`Get` round-trip; TTL expiry; `Del`; `Flush` under a prefix leaves other
  keys alone; `Get` returns independent bytes; errors propagate. Run it for
  `cache.Memory` and the Redis implementation.
- `cache/redis` integration test gated on `REDIS_URL` + `REQUIRE_REDIS`,
  mirroring `example/pg_integration_test.go`, plus a CI service container.

## Work breakdown

- [ ] Add a key prefix (or namespace) to the cache path; define `Flush` as
      prefix-scoped.
- [ ] Add the epoch key + epoch-in-key scheme to `CachedResolver`.
- [ ] Make the cache error policy configurable (fail-closed vs fallback).
- [ ] Add singleflight around resolution.
- [ ] Implement `cache/redis` against `authz.Cache`.
- [ ] Add `cache/cachetest` and run it for memory + redis.
- [ ] Add the Redis integration test and a CI service container.
- [ ] Update `README.md`, `docs/philosophy.md`, and this doc.

## Open questions

- Epoch-in-key vs a generation checked at `Set`: round-trips vs complexity.
- Local epoch cache TTL: how much staleness is acceptable for role edits?
- Should fallback-on-cache-error be the default for a shared cache, or opt-in?
- One shared Redis for everything, or a separate database/instance for authz
  keys?

## Non-goals

- Distributed locking around resolution.
- Pub/Sub invalidation (the epoch already gives prompt role-definition
  invalidation).
- Consistent hashing / sharding of the cache.
- Replacing the resolver; the database stays the source of truth.
