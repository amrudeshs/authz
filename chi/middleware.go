// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

// Package chi adapts the authz core to the chi router. The core stays
// framework-free; this adapter is the only place that knows about chi.
package chi

import (
	"encoding/json"
	"net/http"
	"strings"

	gochi "github.com/go-chi/chi/v5"

	"github.com/amrudeshs/authz"
)

// Resolver is the host hook the middleware needs. Resolve returns the
// caller's permission set (ok=false → 401). HasMembership reports whether the
// caller belongs to the routed tenant (false → 404 existence hiding).
type Resolver interface {
	Resolve(r *http.Request) (set authz.PermissionSet, ok bool)
	HasMembership(r *http.Request) bool
}

// Middleware gates requests by codename using the route pattern chi matched.
//
//	Routes maps "METHOD /path" to its codename. PublicRoutes is the explicit
//	allowlist of "METHOD /path" patterns that bypass the gate; the generated
//	PublicRoutes var holds every x-public operation.
//
// The default is DENY. A route chi matched inside the gated group but present
// in neither map is a misconfiguration — the router and the policy map have
// drifted apart — so it is refused rather than let through. Public access
// must be declared, never inferred from an absent policy.
//
// Apply it to a route group (or via With) so chi has already matched the
// route when the middleware runs:
//
//	r.Group(func(g chi.Router) {
//	    g.Use(mw.Handler)
//	    g.Get("/projects", listProjects)
//	})
type Middleware struct {
	Resolver     Resolver
	Routes       map[string]string
	PublicRoutes map[string]bool
	StripPrefix  string // optional mount prefix stripped from the route pattern
}

// Handler is a chi middleware: http.Handler -> http.Handler.
func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pattern := gochi.RouteContext(r.Context()).RoutePattern()
		if m.StripPrefix != "" {
			pattern = strings.TrimPrefix(pattern, m.StripPrefix)
		}
		key := strings.ToUpper(r.Method) + " " + pattern
		codename, gated := m.Routes[key]
		if !gated {
			if m.PublicRoutes[key] {
				next.ServeHTTP(w, r)
				return
			}
			// Fail closed: chi matched a route with no policy. Denying here is
			// what stops a route added without regenerating RoutePermissions
			// from silently becoming public.
			deny(w, http.StatusInternalServerError, "server misconfigured")
			return
		}
		if m.Resolver == nil {
			deny(w, http.StatusInternalServerError, "server misconfigured")
			return
		}
		set, ok := m.Resolver.Resolve(r)
		if !ok {
			deny(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !m.Resolver.HasMembership(r) {
			deny(w, http.StatusNotFound, "not found")
			return
		}
		if !set.Has(codename) {
			deny(w, http.StatusForbidden, "permission denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func deny(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
