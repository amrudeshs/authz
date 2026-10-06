// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	gochi "github.com/go-chi/chi/v5"

	"github.com/amrudeshs/authz"
	cachemem "github.com/amrudeshs/authz/cache"
	authzchi "github.com/amrudeshs/authz/chi"
)

// The example stubs identity (a bearer token → user) and tenant routing
// (the X-Workspace header → workspace). Real hosts replace these with their
// session and tenancy middleware; the authz seam is unchanged.

type ctxKey int

const (
	userCtx ctxKey = iota
	workspaceCtx
)

func userFrom(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userCtx).(User)
	return u, ok
}

func workspaceFrom(ctx context.Context) (Workspace, bool) {
	w, ok := ctx.Value(workspaceCtx).(Workspace)
	return w, ok
}

type server struct {
	store Store
	authz *authz.CachedResolver
}

func newServer(store Store) *server {
	return &server{
		store: store,
		authz: &authz.CachedResolver{
			Inner: store,
			Cache: cachemem.NewMemory(),
			TTL:   time.Minute,
			Key:   func(ws, user int64) string { return fmt.Sprintf("perms:%d:%d", ws, user) },
			Options: authz.Options{
				WildcardRoleSlug: "owner", // the system admin role
			},
			VocabFn: func() []string { return Vocabulary },
		},
	}
}

// ---- stub identity + tenant routing ----

func (s *server) identity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if token != "" {
			u, ok, err := s.store.UserByToken(r.Context(), token)
			if err != nil {
				// A presented credential that cannot be checked is not an
				// anonymous request. Mapping it to "no user" becomes a 401
				// and hides the outage.
				writeErr(w, http.StatusInternalServerError, "internal error")
				return
			}
			if ok {
				r = r.WithContext(context.WithValue(r.Context(), userCtx, u))
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) workspace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slug := r.Header.Get("X-Workspace"); slug != "" {
			ws, ok, err := s.store.WorkspaceBySlug(r.Context(), slug)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "internal error")
				return
			}
			if ok {
				r = r.WithContext(context.WithValue(r.Context(), workspaceCtx, ws))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---- the chi.Resolver the adapter calls ----

func (s *server) Resolve(r *http.Request) (authz.PermissionSet, error) {
	u, ok := userFrom(r.Context())
	if !ok {
		return authz.PermissionSet{}, authzchi.ErrUnauthenticated
	}
	ws, ok := workspaceFrom(r.Context())
	if !ok {
		// Authenticated, no workspace. HasMembership returns false → 404.
		return authz.PermissionSet{}, nil
	}
	return s.authz.ResolveFor(r.Context(), s.authz.Key(ws.ID, u.ID), ws.ID, u.ID)
}

func (s *server) HasMembership(r *http.Request) (bool, error) {
	u, uok := userFrom(r.Context())
	ws, wok := workspaceFrom(r.Context())
	if !uok || !wok {
		return false, nil
	}
	return s.store.IsMember(r.Context(), ws.ID, u.ID)
}

// ---- router ----

func (s *server) router() http.Handler {
	r := gochi.NewRouter()
	r.Use(s.identity)
	r.Use(s.workspace)

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mw := authzchi.Middleware{Resolver: s, Routes: RoutePermissions, PublicRoutes: PublicRoutes}
	r.Group(func(g gochi.Router) {
		g.Use(mw.Handler)
		g.Get("/projects", s.listProjects)
		g.Post("/projects", s.createProject)
		g.Get("/projects/{id}", s.getProject)
		g.Delete("/projects/{id}", s.deleteProject)
		g.Get("/projects/{id}/tasks", s.listTasks)
		g.Post("/projects/{id}/tasks", s.createTask)
		g.Post("/tasks/{id}/complete", s.completeTask)
		g.Get("/roles", s.listRoles)
		g.Post("/roles", s.createRole)
		g.Post("/roles/{slug}/permissions", s.setRolePermission)
		g.Post("/members/{userId}/roles/{slug}", s.assignRole)
		g.Delete("/members/{userId}/roles/{slug}", s.unassignRole)
	})
	return r
}

// ---- handlers (function-level already authorized; data-level here) ----

func (s *server) listProjects(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	items, err := s.store.ListProjects(r.Context(), ws.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createProject(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	u, _ := userFrom(r.Context())
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeErr(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	p, err := s.store.CreateProject(r.Context(), ws.ID, u.ID, body.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *server) getProject(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	p, ok, err := s.store.GetProject(r.Context(), ws.ID, pathID(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *server) deleteProject(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	ok, err := s.store.DeleteProject(r.Context(), ws.ID, pathID(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *server) listTasks(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	items, err := s.store.ListTasks(r.Context(), ws.ID, pathID(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createTask(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	var body struct {
		Title string `json:"title"`
	}
	if !decode(w, r, &body) {
		return
	}
	t, ok, err := s.store.CreateTask(r.Context(), ws.ID, pathID(r), body.Title)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *server) completeTask(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	ok, err := s.store.CompleteTask(r.Context(), ws.ID, pathID(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

func (s *server) listRoles(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	items, err := s.store.ListRoles(r.Context(), ws.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createRole(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	var body struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Slug == "" {
		writeErr(w, http.StatusUnprocessableEntity, "slug is required")
		return
	}
	if body.Slug == s.authz.Options.WildcardRoleSlug {
		writeErr(w, http.StatusConflict, errReservedSlug.Error())
		return
	}
	if err := s.store.CreateRole(r.Context(), ws.ID, body.Slug, body.Name); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"slug": body.Slug})
}

func (s *server) setRolePermission(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	slug := gochi.URLParam(r, "slug")
	var body struct {
		Codename string `json:"codename"`
		Allow    bool   `json:"allow"`
	}
	if !decode(w, r, &body) {
		return
	}
	ok, err := s.store.SetRolePermission(r.Context(), ws.ID, slug, body.Codename, body.Allow)
	if errors.Is(err, errSystemRole) {
		writeErr(w, http.StatusForbidden, "system roles are immutable")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "role not found")
		return
	}
	// A role-definition change affects every holder. A failed flush is a 500:
	// the write landed, but leaving the cache silently stale is the defect.
	if err := s.authz.Flush(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "codename": body.Codename, "allow": body.Allow})
}

func (s *server) assignRole(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	userID, _ := strconv.ParseInt(gochi.URLParam(r, "userId"), 10, 64)
	slug := gochi.URLParam(r, "slug")
	ok, err := s.store.AssignRole(r.Context(), ws.ID, userID, slug)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "member or role not found")
		return
	}
	if err := s.authz.Invalidate(r.Context(), s.authz.Key(ws.ID, userID)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"userId": userID, "slug": slug})
}

func (s *server) unassignRole(w http.ResponseWriter, r *http.Request) {
	ws, _ := workspaceFrom(r.Context())
	userID, _ := strconv.ParseInt(gochi.URLParam(r, "userId"), 10, 64)
	slug := gochi.URLParam(r, "slug")
	ok, err := s.store.UnassignRole(r.Context(), ws.ID, userID, slug)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "member or role not found")
		return
	}
	if err := s.authz.Invalidate(r.Context(), s.authz.Key(ws.ID, userID)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"userId": userID, "slug": slug, "assigned": false})
}

// ---- small helpers ----

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(gochi.URLParam(r, "id"), 10, 64)
	return id
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
