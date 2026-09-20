// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

const fixture = `{
  "x-permissions": ["tenant.manage"],
  "x-role-seed": {
    "editor": ["project.write", "project.read"],
    "member": ["project.read"]
  },
  "paths": {
    "/projects": {
      "get":  {"operationId": "listProjects"},
      "post": {"operationId": "createProject"}
    },
    "/health": {
      "get": {"operationId": "health", "x-public": true}
    }
  }
}`

func TestGenerateArtifacts(t *testing.T) {
	src, err := generate([]byte(fixture), "main")
	if err != nil {
		t.Fatal(err)
	}
	// gofmt aligns map literals; collapse whitespace so assertions are
	// independent of column padding.
	got := strings.Join(strings.Fields(string(src)), " ")

	for _, want := range []string{
		`"createProject"`,                   // operationId in the vocabulary
		`"listProjects"`,                    // operationId in the vocabulary
		`"health"`,                          // public op still in the vocabulary
		`"tenant.manage"`,                   // x-permissions capability
		`"GET /projects": "listProjects"`,   // route map
		`"POST /projects": "createProject"`, // route map
		`"GET /health": true`,               // public allowlist
		`"member"`,                          // role seed
		`"project.write"`,                   // role seed codename
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated output missing %s\n%s", want, got)
		}
	}

	// Public operations are kept out of the codename map: they appear only in
	// the explicit PublicRoutes allowlist, never as a gated route.
	if strings.Contains(got, `"GET /health": "health"`) {
		t.Fatalf("public route must not appear in RoutePermissions\n%s", got)
	}
}

func TestGenerateDeterministic(t *testing.T) {
	a, err := generate([]byte(fixture), "main")
	if err != nil {
		t.Fatal(err)
	}
	b, err := generate([]byte(fixture), "main")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("generation must be deterministic")
	}
}
