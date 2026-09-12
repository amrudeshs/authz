// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

// Package authz implements the function-level permission layer of a
// multi-tenant RBAC design (Django-style ergonomics, database-enforced):
// permission codenames form a static vocabulary; roles are tenant data
// bundling codenames; members hold roles via their membership.
//
// The package is intentionally dependency-free (no storage, no cache, no
// framework imports): storage is the Resolver interface, caching the Cache
// interface, both supplied by the host application. This keeps the core
// small and portable; the reference schema, the OpenAPI vocabulary
// generator, the chi adapter and the example service live in sibling
// packages in this module.
package authz

import (
	"context"
	"encoding/json"
	"time"
)

// PermissionSet is the resolved authorization state of one member on one
// tenant: the role slugs they hold and the permission codenames those roles
// grant. All checks are set membership — string compares, never reflection.
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

// Resolver is the storage contract the host application implements.
// Implementations MUST be tenant-scoped by construction (structural
// tenancy: an unscoped query is a defect, not an option).
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
	// Empty disables wildcarding.
	WildcardRoleSlug string
}

// Resolve computes the member's PermissionSet. Wildcard members skip the
// codename query entirely.
func Resolve(ctx context.Context, r Resolver, tenantID, userID int64,
	vocabulary []string, opts Options) (PermissionSet, error) {

	slugs, err := r.RoleSlugs(ctx, tenantID, userID)
	if err != nil {
		return PermissionSet{}, err
	}
	ps := PermissionSet{RoleSlugs: slugs}
	if opts.WildcardRoleSlug != "" && ps.HasRole(opts.WildcardRoleSlug) {
		ps.all = true
		ps.Permissions = vocabulary
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

// Cache is the caching contract (e.g. Redis with a safety-net TTL).
// Implementations must treat values as opaque bytes.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration)
	Del(ctx context.Context, key string)
}

// CachedResolver decorates a Resolver with a permission cache. The cache
// key granularity is the HOST's choice via ResolveFor (per-session token is
// the recommended form: tokens are random, so identity reuse — e.g. test
// resets that restart IDENTITY sequences — cannot inherit a stale set).
// Callers must Invalidate on membership/role changes (request-time
// freshness: a stale gate is a defect, not a TTL wait).
type CachedResolver struct {
	Inner   Resolver
	Cache   Cache
	TTL     time.Duration
	Key     func(tenantID, userID int64) string // default key for Resolve
	Options Options
	VocabFn func() []string // vocabulary provider (invoked on resolve)
}

// Resolve computes (or fetches) the member's PermissionSet using the
// default key.
func (cr *CachedResolver) Resolve(ctx context.Context, tenantID, userID int64) (PermissionSet, error) {
	return cr.ResolveFor(ctx, cr.key(tenantID, userID), tenantID, userID)
}

// ResolveFor computes (or fetches) the member's PermissionSet under an
// explicit cache key. An empty key bypasses the cache (per-request
// resolution). Resolution errors propagate; cache corruption is treated as
// a miss, never an error.
func (cr *CachedResolver) ResolveFor(ctx context.Context, cacheKey string, tenantID, userID int64) (PermissionSet, error) {
	if cr.Cache != nil && cacheKey != "" {
		if raw, ok := cr.Cache.Get(ctx, cacheKey); ok {
			var ps PermissionSet
			if json.Unmarshal(raw, &ps) == nil {
				return ps, nil
			}
		}
	}
	ps, err := Resolve(ctx, cr.Inner, tenantID, userID, cr.vocabulary(), cr.Options)
	if err != nil {
		return PermissionSet{}, err
	}
	if cr.Cache != nil && cacheKey != "" {
		if raw, jerr := json.Marshal(ps); jerr == nil {
			cr.Cache.Set(ctx, cacheKey, raw, cr.TTL)
		}
	}
	return ps, nil
}

// Invalidate drops one cache entry (call on membership/role changes under
// the same key discipline the entries were written with).
func (cr *CachedResolver) Invalidate(ctx context.Context, cacheKey string) {
	if cr.Cache != nil && cacheKey != "" {
		cr.Cache.Del(ctx, cacheKey)
	}
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
