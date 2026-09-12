// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// stubResolver is a canned Resolver; roleByUser maps userID → slugs,
// permsByRole maps slug → codenames.
type stubResolver struct {
	roleByUser  map[int64][]string
	permsByRole map[string][]string
	calls       int
}

func (s *stubResolver) RoleSlugs(_ context.Context, _, userID int64) ([]string, error) {
	s.calls++
	return s.roleByUser[userID], nil
}

func (s *stubResolver) PermissionCodenames(_ context.Context, _ int64, slugs []string) ([]string, error) {
	s.calls++
	var out []string
	for _, slug := range slugs {
		out = append(out, s.permsByRole[slug]...)
	}
	return out, nil
}

type mapCache struct{ m map[string][]byte }

func (c *mapCache) Get(_ context.Context, k string) ([]byte, bool) {
	v, ok := c.m[k]
	return v, ok
}
func (c *mapCache) Set(_ context.Context, k string, v []byte, _ time.Duration) {
	if c.m == nil {
		c.m = map[string][]byte{}
	}
	c.m[k] = v
}
func (c *mapCache) Del(_ context.Context, k string) { delete(c.m, k) }

var vocab = []string{"a.create", "b.read", "c.grade"}

func newStub() *stubResolver {
	return &stubResolver{
		roleByUser: map[int64][]string{
			1: {"admin"},
			2: {"author"},
			3: {"student"},
			4: {}, // member with no roles
		},
		permsByRole: map[string][]string{
			"author": {"a.create", "b.read"},
		},
	}
}

func TestWildcardRoleGrantsEverything(t *testing.T) {
	ps, err := Resolve(context.Background(), newStub(), 7, 1, vocab,
		Options{WildcardRoleSlug: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range vocab {
		if !ps.Has(c) {
			t.Fatalf("admin must hold %q", c)
		}
	}
	if !ps.Has("notInTheVocabulary") {
		t.Fatal("wildcard must grant even unknown codenames")
	}
	if !ps.HasRole("admin") {
		t.Fatal("admin slug missing")
	}
}

func TestRolePermissionsAndDenyByDefault(t *testing.T) {
	ps, err := Resolve(context.Background(), newStub(), 7, 2, vocab, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !ps.Has("a.create") || !ps.Has("b.read") {
		t.Fatal("author set wrong")
	}
	if ps.Has("c.grade") {
		t.Fatal("author must not hold evaluator-only codenames")
	}
	student, _ := Resolve(context.Background(), newStub(), 7, 3, vocab, Options{})
	if student.Has("a.create") {
		t.Fatal("student must hold nothing")
	}
	bare, _ := Resolve(context.Background(), newStub(), 7, 4, vocab, Options{})
	if bare.Has("a.create") || bare.HasRole("author") {
		t.Fatal("role-less member must hold nothing")
	}
}

func TestCachedResolverCachesAndInvalidates(t *testing.T) {
	cache := &mapCache{}
	inner := newStub()
	cr := &CachedResolver{
		Inner: inner, Cache: cache, TTL: time.Minute,
		Options: Options{WildcardRoleSlug: "admin"},
		VocabFn: func() []string { return vocab },
	}
	ctx := context.Background()
	if _, err := cr.ResolveFor(ctx, "k", 7, 2); err != nil {
		t.Fatal(err)
	}
	callsAfterFirst := inner.calls // RoleSlugs + PermissionCodenames
	if _, err := cr.ResolveFor(ctx, "k", 7, 2); err != nil {
		t.Fatal(err)
	}
	if inner.calls != callsAfterFirst {
		t.Fatalf("second resolve must hit the cache: %d → %d inner calls",
			callsAfterFirst, inner.calls)
	}
	cr.Invalidate(ctx, "k")
	if _, err := cr.ResolveFor(ctx, "k", 7, 2); err != nil {
		t.Fatal(err)
	}
	if inner.calls != callsAfterFirst*2 {
		t.Fatalf("invalidate must force re-resolution: %d calls", inner.calls)
	}
}

func TestResolveForEmptyKeyBypassesCache(t *testing.T) {
	cache := &mapCache{}
	inner := newStub()
	cr := &CachedResolver{
		Inner: inner, Cache: cache, TTL: time.Minute,
		VocabFn: func() []string { return vocab },
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := cr.ResolveFor(ctx, "", 7, 2); err != nil {
			t.Fatal(err)
		}
	}
	if len(cache.m) != 0 {
		t.Fatal("empty key must bypass the cache")
	}
	if inner.calls != 4 {
		t.Fatalf("each resolve must hit the resolver, got %d calls", inner.calls)
	}
}

func TestWildcardCachedResolution(t *testing.T) {
	cr := &CachedResolver{
		Inner: newStub(), TTL: time.Minute,
		Options: Options{WildcardRoleSlug: "admin"},
		VocabFn: func() []string { return vocab },
	}
	ps, err := cr.Resolve(context.Background(), 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ps.All() || !ps.Has("anything") {
		t.Fatal("wildcard admin must surface All + full grant")
	}
}

// ---- error propagation + nil-default tails ----

type errResolver struct {
	roleErr error
	permErr error
}

func (s *errResolver) RoleSlugs(_ context.Context, _, _ int64) ([]string, error) {
	if s.roleErr != nil {
		return nil, s.roleErr
	}
	return []string{"author"}, nil
}

func (s *errResolver) PermissionCodenames(_ context.Context, _ int64, _ []string) ([]string, error) {
	if s.permErr != nil {
		return nil, s.permErr
	}
	return []string{"a.create"}, nil
}

// Resolve propagates RoleSlugs failures (the auth middleware's fail-closed
// contract: an unreadable set never widens access).
func TestResolvePropagatesRoleSlugError(t *testing.T) {
	boom := context.DeadlineExceeded
	_, err := Resolve(context.Background(), &errResolver{roleErr: boom}, 7, 2, vocab, Options{})
	if err != boom {
		t.Fatalf("err = %v, want the RoleSlugs failure", err)
	}
}

// Resolve propagates PermissionCodenames failures.
func TestResolvePropagatesPermissionCodenameError(t *testing.T) {
	boom := context.DeadlineExceeded
	_, err := Resolve(context.Background(), &errResolver{permErr: boom}, 7, 2, vocab, Options{})
	if err != boom {
		t.Fatalf("err = %v, want the PermissionCodenames failure", err)
	}
}

// ResolveFor propagates inner-resolution failures (the cache must not
// mask a storage outage).
func TestResolveForPropagatesInnerError(t *testing.T) {
	boom := context.DeadlineExceeded
	cr := &CachedResolver{
		Inner: &errResolver{permErr: boom}, TTL: time.Minute,
		VocabFn: func() []string { return vocab },
	}
	if _, err := cr.ResolveFor(context.Background(), "k", 7, 2); err != boom {
		t.Fatalf("err = %v, want the inner failure", err)
	}
}

// Cache CORRUPTION is a miss, never an error: a garbage entry is dropped
// and the resolver re-resolves.
func TestResolveForCacheCorruptionIsAMiss(t *testing.T) {
	cache := &mapCache{m: map[string][]byte{"k": []byte("{corrupt")}}
	inner := newStub()
	cr := &CachedResolver{
		Inner: inner, Cache: cache, TTL: time.Minute,
		VocabFn: func() []string { return vocab },
	}
	ps, err := cr.ResolveFor(context.Background(), "k", 7, 2)
	if err != nil {
		t.Fatalf("corrupt cache must degrade to a miss: %v", err)
	}
	if !ps.Has("a.create") {
		t.Fatal("post-corruption resolve must return the fresh set")
	}
	if !ps.HasRole("author") {
		t.Fatal("fresh set must carry role slugs")
	}
}

// Resolve with Key == nil bypasses the cache (default-key discipline).
func TestResolveNilKeyBypassesCache(t *testing.T) {
	cache := &mapCache{}
	cr := &CachedResolver{
		Inner: newStub(), Cache: cache, TTL: time.Minute,
		VocabFn: func() []string { return vocab },
	}
	if _, err := cr.Resolve(context.Background(), 7, 2); err != nil {
		t.Fatal(err)
	}
	if len(cache.m) != 0 {
		t.Fatal("nil Key must bypass the cache — entries would be unreachable for invalidation")
	}
}

// Resolve with VocabFn == nil: wildcard resolution with an empty
// vocabulary surfaces the wildcard grant but no codenames.
func TestVocabularyNilTail(t *testing.T) {
	cr := &CachedResolver{
		Inner: newStub(), TTL: time.Minute,
		Options: Options{WildcardRoleSlug: "admin"},
		// VocabFn deliberately nil
	}
	ps, err := cr.Resolve(context.Background(), 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ps.All() {
		t.Fatal("wildcard must still flag All")
	}
	if len(ps.Permissions) != 0 {
		t.Fatalf("nil vocabulary must surface no codenames, got %v", ps.Permissions)
	}
}

// Resolve consults the default key when set — the cache entry lands under
// the host's key discipline and invalidation finds it there.
func TestResolveUsesDefaultKey(t *testing.T) {
	cache := &mapCache{}
	cr := &CachedResolver{
		Inner: newStub(), Cache: cache, TTL: time.Minute,
		Key: func(tenantID, userID int64) string {
			return fmt.Sprintf("perms:%d:%d", tenantID, userID)
		},
		VocabFn: func() []string { return vocab },
	}
	ctx := context.Background()
	if _, err := cr.Resolve(ctx, 7, 2); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Get(ctx, "perms:7:2"); !ok {
		t.Fatal("default key must land the entry under the host's discipline")
	}
	// Invalidate under the same discipline finds it
	cr.Invalidate(ctx, "perms:7:2")
	if _, ok := cache.Get(ctx, "perms:7:2"); ok {
		t.Fatal("invalidate must drop the default-key entry")
	}
}
