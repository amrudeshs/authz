// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package chi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	gochi "github.com/go-chi/chi/v5"

	"github.com/amrudeshs/authz"
)

type stubResolver struct {
	authed bool
	member bool
	perms  []string
}

func (s stubResolver) Resolve(*http.Request) (authz.PermissionSet, bool) {
	return authz.PermissionSet{Permissions: s.perms}, s.authed
}
func (s stubResolver) HasMembership(*http.Request) bool { return s.member }

// slugResolver is a minimal authz.Resolver used to build a real wildcard set.
type slugResolver struct{ slug string }

func (s slugResolver) RoleSlugs(_ context.Context, _, _ int64) ([]string, error) {
	return []string{s.slug}, nil
}
func (s slugResolver) PermissionCodenames(_ context.Context, _ int64, _ []string) ([]string, error) {
	return nil, nil
}

// wildcardResolver produces a genuine wildcard permission set via authz.Resolve.
type wildcardResolver struct{ stubResolver }

func (w wildcardResolver) Resolve(r *http.Request) (authz.PermissionSet, bool) {
	ps, _ := authz.Resolve(r.Context(), slugResolver{"owner"}, 1, 1, nil,
		authz.Options{WildcardRoleSlug: "owner"})
	return ps, w.authed
}

func router(res Resolver) http.Handler {
	r := gochi.NewRouter()
	mw := Middleware{
		Resolver: res,
		Routes: map[string]string{
			"GET /projects": "project.read",
		},
		PublicRoutes: map[string]bool{
			"GET /status": true,
		},
	}.Handler
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	r.Get("/health", ok) // public: outside the gated group
	r.Group(func(g gochi.Router) {
		g.Use(mw)
		g.Get("/projects", ok)
		g.Get("/status", ok)   // explicitly public inside the gated group
		g.Get("/unmapped", ok) // matched, but no policy: must fail closed
	})
	return r
}

func call(h http.Handler, method, path string) int {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestMiddlewareSemantics(t *testing.T) {
	cases := []struct {
		name string
		res  stubResolver
		path string
		want int
	}{
		{"public route passes through", stubResolver{}, "/health", http.StatusOK},
		{"explicit public route in group passes through", stubResolver{}, "/status", http.StatusOK},
		{"no session -> 401", stubResolver{authed: false}, "/projects", http.StatusUnauthorized},
		{"no membership -> 404", stubResolver{authed: true, member: false}, "/projects", http.StatusNotFound},
		{"missing codename -> 403", stubResolver{authed: true, member: true, perms: []string{"other"}}, "/projects", http.StatusForbidden},
		{"granted -> 200", stubResolver{authed: true, member: true, perms: []string{"project.read"}}, "/projects", http.StatusOK},
		{"unmapped route -> 500 (fail closed)", stubResolver{authed: true, member: true, perms: []string{"project.read"}}, "/unmapped", http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := call(router(tc.res), "GET", tc.path); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWildcardGrantsGatedRoute(t *testing.T) {
	res := wildcardResolver{stubResolver{authed: true, member: true}}
	r := gochi.NewRouter()
	r.Group(func(g gochi.Router) {
		g.Use(Middleware{Resolver: res, Routes: map[string]string{
			"GET /projects": "project.read",
		}}.Handler)
		g.Get("/projects", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	})

	if got := call(r, "GET", "/projects"); got != http.StatusOK {
		t.Fatalf("wildcard admin must pass, got %d", got)
	}
}

// A route registered inside the gated group but absent from both policy maps
// is a misconfiguration: even a wildcard admin must be refused. This is the
// regression guard for the old fail-open default where an unmapped route was
// silently treated as public.
func TestUnmappedRouteFailsClosedEvenForWildcard(t *testing.T) {
	res := wildcardResolver{stubResolver{authed: true, member: true}}
	r := gochi.NewRouter()
	r.Group(func(g gochi.Router) {
		g.Use(Middleware{Resolver: res, Routes: map[string]string{
			"GET /projects": "project.read",
		}}.Handler)
		g.Get("/projects", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		g.Get("/shadow", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	})

	if got := call(r, "GET", "/shadow"); got != http.StatusInternalServerError {
		t.Fatalf("unmapped route = %d, want 500 (fail closed)", got)
	}
}
