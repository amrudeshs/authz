// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

// Package authz implements the function-level permission layer of a
// multi-tenant RBAC design: permission codenames form a static vocabulary;
// roles are tenant data bundling codenames; members hold roles via their
// membership.
//
// The package is intentionally dependency-free (no storage, no cache, no
// framework imports): storage is the Resolver interface, caching the Cache
// interface, both supplied by the host application. This keeps the core
// small and portable; the reference schema, the OpenAPI vocabulary
// generator, the chi adapter and the example service live in sibling
// packages in this module.
//
// This layer answers "may this member call this operation?" It does not
// answer "which rows may they see?" Row filters stay in the host's SQL.
package authz

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"
)

// PermissionSet is the resolved authorization state of one member on one
// tenant: the role slugs they hold and the permission codenames those roles
// grant. All checks are set membership — string compares, never reflection.
//
// The wildcard flag is unexported so only Resolve can set it, and it is part
// of the JSON form so a cache round-trip does not drop it. CachedResolver
// also recomputes it on a hit from RoleSlugs and Options, so a hit agrees
// with the process's current wildcard slug even if the blob is old.
type PermissionSet struct {
	RoleSlugs   []string
	Permissions []string

	all bool // wildcard: the member's wildcard role grants the whole vocabulary
}

// Has reports whether the set grants codename. Wildcard sets grant
// everything, including codenames unknown at resolution time.
func (s PermissionSet) Has(codename string) bool {
	if s.all {
		return true
	}
	for _, p := range s.Permissions {
		if p == codename {
			return true
		}
	}
	return false
}

// HasRole reports whether the member holds the given role slug. Role-scoped
// behavior (scope branching, target-role requirements) checks slugs; plain
// capability gates should prefer Has.
func (s PermissionSet) HasRole(slug string) bool {
	for _, r := range s.RoleSlugs {
		if r == slug {
			return true
		}
	}
	return false
}

// All reports the wildcard state (the member's wildcard role grants the
// full vocabulary — surfaces as "every codename" to clients).
func (s PermissionSet) All() bool { return s.all }

// MarshalJSON includes the wildcard flag. encoding/json would otherwise drop
// the unexported field and a cache hit would not be a wildcard set.
func (s PermissionSet) MarshalJSON() ([]byte, error) {
	type wire struct {
		RoleSlugs   []string
		Permissions []string
		All         bool `json:"all"`
	}
	return json.Marshal(wire{
		RoleSlugs:   s.RoleSlugs,
		Permissions: s.Permissions,
		All:         s.all,
	})
}

// UnmarshalJSON restores the wildcard flag. A blob written before the flag
// was persisted unmarshals with All false; CachedResolver recomputes it.
func (s *PermissionSet) UnmarshalJSON(b []byte) error {
	type wire struct {
		RoleSlugs   []string
		Permissions []string
		All         bool `json:"all"`
	}
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*s = PermissionSet{RoleSlugs: w.RoleSlugs, Permissions: w.Permissions, all: w.All}
	return nil
}

// Resolver is the storage contract the host application implements.
// Implementations must scope every query to the tenantID argument. The core
// passes the id through and cannot check the result; an unscoped query is a
// defect in the implementation. The reference query in example/pgstore.go
// filters both the membership and the role by tenant, and the reference
// schema rejects a binding whose role belongs to another tenant.
type Resolver interface {
	// RoleSlugs returns the member's role slugs on the tenant (active
	// roles only; soft-deleted roles grant nothing).
	RoleSlugs(ctx context.Context, tenantID, userID int64) ([]string, error)
	// PermissionCodenames returns the union of permission codenames bound
	// to the given role slugs on the tenant.
	PermissionCodenames(ctx context.Context, tenantID int64, slugs []string) ([]string, error)
}

// Options configures resolution.
type Options struct {
	// WildcardRoleSlug: members holding this role slug pass EVERY check
	// and surface the full vocabulary (the system administrator role).
	// Empty disables wildcarding. The slug is reserved: hosts should refuse
	// to create a custom role with this name, or an unseeded tenant can
	// mint an admin by inserting it.
	WildcardRoleSlug string
}

// Resolve computes the member's PermissionSet. Wildcard members skip the
// codename query entirely. The vocabulary slice is copied; callers can
// mutate the returned Permissions without changing the host's vocabulary.
func Resolve(ctx context.Context, r Resolver, tenantID, userID int64,
	vocabulary []string, opts Options) (PermissionSet, error) {

	slugs, err := r.RoleSlugs(ctx, tenantID, userID)
	if err != nil {
		return PermissionSet{}, err
	}
	ps := PermissionSet{RoleSlugs: slugs}
	if opts.WildcardRoleSlug != "" && ps.HasRole(opts.WildcardRoleSlug) {
		ps.all = true
		ps.Permissions = copyStrings(vocabulary)
		return ps, nil
	}
	if len(slugs) == 0 {
		return ps, nil
	}
	perms, err := r.PermissionCodenames(ctx, tenantID, slugs)
	if err != nil {
		return PermissionSet{}, err
	}
	ps.Permissions = perms
	return ps, nil
}

// Cache is the caching contract (for example Redis, or cache.Memory).
// Values are opaque bytes. Get reports a miss with ok=false and a nil error;
// a non-nil error is an outage, not a miss. Set, Del, and Flush report
// failure so the host can fail closed instead of leaving a stale gate.
// Flush drops every entry — role-definition edits affect every holder, and a
// type-assert to a concrete cache is not the contract.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
	Del(ctx context.Context, key string) error
	Flush(ctx context.Context) error
}

// CachedResolver decorates a Resolver with a permission cache.
//
// The cache key must be recomputable by whoever invalidates. The key this
// type can drop with Invalidate is a function of tenant and user — the
// example uses perms:{tenantID}:{userID}. A session component defeats
// identity reuse, but then a membership change cannot find the keys unless
// the host keeps an index or calls Flush. Do not use a key you cannot
// recompute.
//
// Invalidate drops one key. Flush drops every holder. Both bump a generation
// so an in-flight ResolveFor does not Set a stale snapshot after the
// invalidation in this process. A Set that races a Flush on another instance
// can still restore a stale entry; TTL bounds that window. TTL is the
// backstop for that race, not the freshness mechanism, and a failed Del or
// Flush is returned rather than ignored.
//
// CachedResolver must not be copied after first use.
type CachedResolver struct {
	Inner   Resolver
	Cache   Cache
	TTL     time.Duration
	Key     func(tenantID, userID int64) string // default key for Resolve
	Options Options
	VocabFn func() []string // vocabulary provider (invoked on resolve and on a wildcard hit)

	gen atomic.Uint64
}

// Resolve computes (or fetches) the member's PermissionSet using the
// default key.
func (cr *CachedResolver) Resolve(ctx context.Context, tenantID, userID int64) (PermissionSet, error) {
	return cr.ResolveFor(ctx, cr.key(tenantID, userID), tenantID, userID)
}

// ResolveFor computes (or fetches) the member's PermissionSet under an
// explicit cache key. An empty key bypasses the cache (per-request
// resolution). Resolution errors and cache I/O errors propagate; cache
// corruption is treated as a miss, never an error.
func (cr *CachedResolver) ResolveFor(ctx context.Context, cacheKey string, tenantID, userID int64) (PermissionSet, error) {
	gen := cr.gen.Load()
	if cr.Cache != nil && cacheKey != "" {
		raw, ok, err := cr.Cache.Get(ctx, cacheKey)
		if err != nil {
			return PermissionSet{}, err
		}
		if ok {
			var ps PermissionSet
			if json.Unmarshal(raw, &ps) == nil {
				return cr.restore(ps), nil
			}
		}
	}
	ps, err := Resolve(ctx, cr.Inner, tenantID, userID, cr.vocabulary(), cr.Options)
	if err != nil {
		return PermissionSet{}, err
	}
	if cr.Cache != nil && cacheKey != "" {
		if cr.gen.Load() != gen {
			return ps, nil
		}
		raw, jerr := json.Marshal(ps)
		if jerr != nil {
			return ps, nil
		}
		if err := cr.Cache.Set(ctx, cacheKey, raw, cr.TTL); err != nil {
			return PermissionSet{}, err
		}
		if cr.gen.Load() != gen {
			if err := cr.Cache.Del(ctx, cacheKey); err != nil {
				return PermissionSet{}, err
			}
		}
	}
	return ps, nil
}

// Invalidate drops one cache entry. Call it on a membership change under the
// same key the entry was written with. A cache error is returned; ignoring
// it leaves a stale gate.
func (cr *CachedResolver) Invalidate(ctx context.Context, cacheKey string) error {
	cr.gen.Add(1)
	if cr.Cache == nil || cacheKey == "" {
		return nil
	}
	return cr.Cache.Del(ctx, cacheKey)
}

// Flush drops every cached set. Call it on a role-definition change. A cache
// error is returned; ignoring it leaves every holder's gate stale until TTL.
func (cr *CachedResolver) Flush(ctx context.Context) error {
	cr.gen.Add(1)
	if cr.Cache == nil {
		return nil
	}
	return cr.Cache.Flush(ctx)
}

// restore makes a cache hit agree with the current wildcard option and
// vocabulary. The stored flag is not trusted: Options may have changed, and
// blobs written before the flag was persisted omit it.
func (cr *CachedResolver) restore(ps PermissionSet) PermissionSet {
	slug := cr.Options.WildcardRoleSlug
	if slug != "" && ps.HasRole(slug) {
		ps.all = true
		ps.Permissions = copyStrings(cr.vocabulary())
		return ps
	}
	ps.all = false
	return ps
}

func (cr *CachedResolver) key(tenantID, userID int64) string {
	if cr.Key == nil {
		return ""
	}
	return cr.Key(tenantID, userID)
}

func (cr *CachedResolver) vocabulary() []string {
	if cr.VocabFn == nil {
		return nil
	}
	return cr.VocabFn()
}

func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
