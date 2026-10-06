// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"testing"
)

// The OpenAPI x-role-seed (via generated RoleSeed) and example/seed.sql must
// be the same matrix. CI regenerates perm_gen.go; this test is what fails
// when the SQL seed drifts, including a missing wildcard role.
func TestSeedSQLMatchesRoleSeed(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "seed.sql"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)seed_role_permissions\('(.*?)'\)`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("example/seed.sql does not call seed_role_permissions")
	}
	var got map[string][]string
	if err := json.Unmarshal(m[1], &got); err != nil {
		t.Fatalf("seed.sql matrix is not JSON: %v", err)
	}
	if len(got) != len(RoleSeed) {
		t.Fatalf("seed.sql has %d roles, RoleSeed has %d", len(got), len(RoleSeed))
	}
	for slug, want := range RoleSeed {
		codes, ok := got[slug]
		if !ok {
			t.Fatalf("seed.sql missing slug %q from x-role-seed", slug)
		}
		if !sameCodes(codes, want) {
			t.Fatalf("slug %q: seed.sql %v, RoleSeed %v", slug, codes, want)
		}
	}
}

func sameCodes(a, b []string) bool {
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	slices.Sort(aa)
	slices.Sort(bb)
	return slices.Equal(aa, bb)
}
