// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// do issues a request through the router with the example's identity/tenant
// headers and returns the recorder.
func do(t *testing.T, h http.Handler, method, path, token, workspace string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if workspace != "" {
		req.Header.Set("X-Workspace", workspace)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newTestServer() http.Handler { return newServer(newMemStore()).router() }

func TestPublicHealthNeedsNoAuth(t *testing.T) {
	h := newTestServer()
	if got := do(t, h, "GET", "/health", "", "", nil).Code; got != http.StatusOK {
		t.Fatalf("health = %d, want 200", got)
	}
}

func TestSessionAndMembershipSemantics(t *testing.T) {
	h := newTestServer()
	cases := []struct {
		name      string
		token     string
		workspace string
		want      int
	}{
		{"no session -> 401", "", "acme", http.StatusUnauthorized},
		{"unknown workspace -> 404", "member-acme", "nope", http.StatusNotFound},
		{"non-member -> 404 (existence hiding)", "owner-globex", "acme", http.StatusNotFound},
		{"member -> 200", "member-acme", "acme", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(t, h, "GET", "/projects", tc.token, tc.workspace, nil).Code; got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestFunctionLevelDenialAndWildcard(t *testing.T) {
	h := newTestServer()

	// member lacks createProject → 403 before the handler.
	if got := do(t, h, "POST", "/projects", "member-acme", "acme", map[string]string{"name": "X"}).Code; got != http.StatusForbidden {
		t.Fatalf("member createProject = %d, want 403", got)
	}
	// editor holds createProject → 201.
	if got := do(t, h, "POST", "/projects", "editor-acme", "acme", map[string]string{"name": "Editor project"}).Code; got != http.StatusCreated {
		t.Fatalf("editor createProject = %d, want 201", got)
	}
	// deleteProject is owner-only (wildcard): editor → 403, owner → 200.
	if got := do(t, h, "DELETE", "/projects/1", "editor-acme", "acme", nil).Code; got != http.StatusForbidden {
		t.Fatalf("editor deleteProject = %d, want 403", got)
	}
	if got := do(t, h, "DELETE", "/projects/1", "owner-acme", "acme", nil).Code; got != http.StatusOK {
		t.Fatalf("owner deleteProject = %d, want 200", got)
	}
}

func TestSystemRoleImmutability(t *testing.T) {
	// A grant to a system role is refused (typed 403) — immutability is
	// enforced even for the wildcard owner.
	h := newTestServer()
	if got := do(t, h, "POST", "/roles/editor/permissions", "owner-acme", "acme",
		map[string]any{"codename": "deleteProject", "allow": true}).Code; got != http.StatusForbidden {
		t.Fatalf("grant to system role = %d, want 403", got)
	}
}

func TestWildcardNeedsNoSeed(t *testing.T) {
	// The wildcard owner can use a brand-new capability without any stored
	// permission rows (createRole is not in the role seed).
	h := newTestServer()
	if got := do(t, h, "POST", "/roles", "owner-acme", "acme",
		map[string]string{"slug": "auditor", "name": "Auditor"}).Code; got != http.StatusCreated {
		t.Fatalf("wildcard createRole = %d, want 201", got)
	}
}

func TestDataLevelWorkspaceScoping(t *testing.T) {
	h := newTestServer()
	// Project 1 lives in acme; the globex owner is a wildcard but the
	// handler scopes by workspace → 404.
	if got := do(t, h, "DELETE", "/projects/1", "owner-globex", "globex", nil).Code; got != http.StatusNotFound {
		t.Fatalf("cross-workspace delete = %d, want 404", got)
	}
}

func TestRoleLifecycleAndCacheInvalidation(t *testing.T) {
	h := newTestServer()

	// member cannot create a project to start with.
	if got := do(t, h, "POST", "/projects", "member-acme", "acme", map[string]string{"name": "N"}).Code; got != http.StatusForbidden {
		t.Fatalf("pre-grant = %d, want 403", got)
	}
	// owner creates a custom role, grants createProject, assigns it.
	if got := do(t, h, "POST", "/roles", "owner-acme", "acme", map[string]string{"slug": "manager", "name": "Manager"}).Code; got != http.StatusCreated {
		t.Fatalf("createRole = %d, want 201", got)
	}
	if got := do(t, h, "POST", "/roles/manager/permissions", "owner-acme", "acme",
		map[string]any{"codename": "createProject", "allow": true}).Code; got != http.StatusOK {
		t.Fatalf("setRolePermission = %d, want 200", got)
	}
	if got := do(t, h, "POST", "/members/3/roles/manager", "owner-acme", "acme", nil).Code; got != http.StatusOK {
		t.Fatalf("assignRole = %d, want 200", got)
	}
	// The member now holds the new capability (cache invalidated on assign).
	if got := do(t, h, "POST", "/projects", "member-acme", "acme", map[string]string{"name": "After grant"}).Code; got != http.StatusCreated {
		t.Fatalf("post-grant = %d, want 201", got)
	}
}

func TestTaskOpsAndProjectScoping(t *testing.T) {
	h := newTestServer()
	// editor creates a task on project 1 (acme).
	if got := do(t, h, "POST", "/projects/1/tasks", "editor-acme", "acme", map[string]string{"title": "New task"}).Code; got != http.StatusCreated {
		t.Fatalf("createTask = %d, want 201", got)
	}
	// creating a task on a project outside the workspace → 404.
	if got := do(t, h, "POST", "/projects/2/tasks", "editor-acme", "acme", map[string]string{"title": "X"}).Code; got != http.StatusNotFound {
		t.Fatalf("cross-workspace createTask = %d, want 404", got)
	}
	if got := do(t, h, "POST", "/tasks/1/complete", "editor-acme", "acme", nil).Code; got != http.StatusOK {
		t.Fatalf("completeTask = %d, want 200", got)
	}
}
