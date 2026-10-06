// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amrudeshs/authz"
)

// Postgres integration tests cover the contracts the in-memory suite cannot
// represent: composite tenancy, the system-role trigger, seed reconciliation,
// and pgStore parity with the demo seed.
//
// They run when DATABASE_URL is set. REQUIRE_POSTGRES=1 turns a missing
// database into a failure instead of a skip, which is how the Docker run and
// CI invoke the full suite.

var pgPool *pgxpool.Pool

func TestMain(m *testing.M) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_POSTGRES") == "1" {
			fmt.Fprintln(os.Stderr, "REQUIRE_POSTGRES=1 but DATABASE_URL is unset")
			os.Exit(1)
		}
		os.Exit(m.Run())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var last error
	for i := 0; i < 30; i++ {
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			err = pool.Ping(ctx)
		}
		if err == nil {
			pgPool = pool
			break
		}
		if pool != nil {
			pool.Close()
		}
		last = err
		time.Sleep(time.Second)
	}
	if pgPool == nil {
		fmt.Fprintf(os.Stderr, "postgres: %v\n", last)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "postgres integration enabled")
	code := m.Run()
	pgPool.Close()
	os.Exit(code)
}

func requirePostgres(t *testing.T) {
	t.Helper()
	if pgPool != nil {
		return
	}
	if os.Getenv("REQUIRE_POSTGRES") == "1" {
		t.Fatal("DATABASE_URL is required")
	}
	t.Skip("DATABASE_URL unset; Postgres integration tests skipped")
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(file))
}

// rebuildDB drops public and reapplies the reference schema. withDemo also
// loads example/seed.sql. The pool is replaced so no connection keeps a
// plan from the dropped schema.
func rebuildDB(t *testing.T, withDemo bool) *pgxpool.Pool {
	t.Helper()
	requirePostgres(t)
	ctx := context.Background()
	dsn := os.Getenv("DATABASE_URL")
	if pgPool != nil {
		pgPool.Close()
		pgPool = nil
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.PgConn().Exec(ctx, `
		DROP SCHEMA IF EXISTS public CASCADE;
		CREATE SCHEMA public;
		GRANT ALL ON SCHEMA public TO postgres;
		GRANT ALL ON SCHEMA public TO public`).ReadAll(); err != nil {
		t.Fatal(err)
	}
	files := []string{"schema/001_authz.sql", "schema/002_seed_function.sql"}
	if withDemo {
		files = append(files, "example/seed.sql")
	}
	root := moduleRoot(t)
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.PgConn().Exec(ctx, string(raw)).ReadAll(); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	pgPool = pool
	return pool
}

func pgErrCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func mustCount(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func idBy(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPostgresSeedAndConstraints(t *testing.T) {
	pool := rebuildDB(t, true)
	ctx := context.Background()

	if got := mustCount(t, pool, `SELECT count(*) FROM roles`); got != 6 {
		t.Fatalf("roles = %d, want 6", got)
	}
	acme := idBy(t, pool, `SELECT id FROM tenants WHERE slug = 'acme'`)
	if got := mustCount(t, pool, `
		SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		WHERE r.tenant_id = $1 AND r.slug = 'editor'`, acme); got != 7 {
		t.Fatalf("acme editor grants = %d, want 7", got)
	}
	if got := mustCount(t, pool, `
		SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		WHERE r.tenant_id = $1 AND r.slug = 'owner'`, acme); got != 0 {
		t.Fatalf("owner grants = %d, want 0", got)
	}

	t.Run("cross-tenant binding rejected", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			INSERT INTO membership_roles (membership_id, role_id, tenant_id)
			SELECT m.id, r.id, m.tenant_id
			FROM memberships m
			JOIN roles r ON r.slug = 'owner' AND r.tenant_id <> m.tenant_id
			LIMIT 1`)
		if err == nil {
			t.Fatal("cross-tenant membership_roles insert succeeded")
		}
		if pgErrCode(err) != "23503" {
			t.Fatalf("code = %s, want 23503 foreign_key_violation: %v", pgErrCode(err), err)
		}
	})

	t.Run("system grant rejected outside the seed function", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_codename)
			SELECT id, 'deleteProject' FROM roles WHERE slug = 'owner' AND is_system LIMIT 1`)
		if err == nil {
			t.Fatal("direct system-role grant succeeded")
		}
		if pgErrCode(err) != "42501" {
			t.Fatalf("code = %s, want 42501: %v", pgErrCode(err), err)
		}
	})

	t.Run("system role row cannot be soft-deleted", func(t *testing.T) {
		_, err := pool.Exec(ctx, `UPDATE roles SET deleted_at = now() WHERE is_system`)
		if err == nil {
			t.Fatal("updating a system role succeeded")
		}
		if pgErrCode(err) != "42501" {
			t.Fatalf("code = %s, want 42501: %v", pgErrCode(err), err)
		}
	})

	t.Run("reseed drops grants for slugs removed from the matrix", func(t *testing.T) {
		_, err := pool.Exec(ctx, `SELECT seed_role_permissions($1::jsonb)`,
			`{"owner":[],"member":["listProjects"]}`)
		if err != nil {
			t.Fatal(err)
		}
		if got := mustCount(t, pool, `
			SELECT count(*) FROM role_permissions rp
			JOIN roles r ON r.id = rp.role_id
			WHERE r.slug = 'editor' AND r.is_system AND r.deleted_at IS NULL`); got != 0 {
			t.Fatalf("editor grants after drop = %d, want 0", got)
		}
		if got := mustCount(t, pool, `
			SELECT count(*) FROM roles
			WHERE slug = 'editor' AND is_system AND deleted_at IS NULL`); got != 2 {
			t.Fatalf("editor role rows = %d, want 2 (row kept, grants revoked)", got)
		}
		if got := mustCount(t, pool, `
			SELECT count(*) FROM role_permissions rp
			JOIN roles r ON r.id = rp.role_id
			WHERE r.slug = 'member' AND r.is_system AND r.deleted_at IS NULL`); got != 2 {
			t.Fatalf("member grants = %d, want 2 (one listProjects per tenant)", got)
		}
	})

	t.Run("seed function ignores the caller search_path", func(t *testing.T) {
		// The function name is still resolved in the caller's search_path.
		// Once it runs, SET search_path on the function must keep unqualified
		// table names on public, even if the caller planted a shadow schema.
		conn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, `
			CREATE SCHEMA evil;
			CREATE TABLE evil.roles (id int);
			CREATE TABLE evil.tenants (id int);
			CREATE TABLE evil.role_permissions (role_id int, permission_codename text);
			SET search_path = evil`); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `SELECT public.seed_role_permissions($1::jsonb)`,
			`{"owner":[],"editor":["listProjects"],"member":["listProjects"]}`); err != nil {
			t.Fatalf("pinned search_path should still write public tables: %v", err)
		}
		var evilRows int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM evil.roles`).Scan(&evilRows); err != nil {
			t.Fatal(err)
		}
		if evilRows != 0 {
			t.Fatalf("seed wrote %d rows into the caller's schema", evilRows)
		}
		if got := mustCount(t, pool, `
			SELECT count(*) FROM public.role_permissions rp
			JOIN public.roles r ON r.id = rp.role_id
			WHERE r.slug = 'editor' AND r.deleted_at IS NULL`); got == 0 {
			t.Fatal("seed did not write editor grants to public")
		}
	})
}

func TestPostgresNewTenantIsSeeded(t *testing.T) {
	pool := rebuildDB(t, false)
	ctx := context.Background()

	var initech int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (slug, name) VALUES ('initech', 'Initech') RETURNING id`).Scan(&initech); err != nil {
		t.Fatal(err)
	}
	if got := mustCount(t, pool, `SELECT count(*) FROM roles WHERE tenant_id = $1`, initech); got != 0 {
		t.Fatalf("roles before any seed = %d, want 0", got)
	}
	if _, err := pool.Exec(ctx, `SELECT seed_role_permissions($1::jsonb)`,
		`{"owner":[],"editor":["listProjects"],"member":["listProjects"]}`); err != nil {
		t.Fatal(err)
	}
	if got := mustCount(t, pool, `SELECT count(*) FROM roles WHERE tenant_id = $1`, initech); got != 3 {
		t.Fatalf("roles after seed = %d, want 3", got)
	}

	var later int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (slug, name) VALUES ('hooli', 'Hooli') RETURNING id`).Scan(&later); err != nil {
		t.Fatal(err)
	}
	if got := mustCount(t, pool, `
		SELECT count(*) FROM roles WHERE tenant_id = $1 AND is_system AND deleted_at IS NULL`, later); got != 3 {
		t.Fatalf("roles on tenant created after seed = %d, want 3", got)
	}
	var ownerGrants int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		WHERE r.tenant_id = $1 AND r.slug = 'owner'`, later).Scan(&ownerGrants); err != nil {
		t.Fatal(err)
	}
	if ownerGrants != 0 {
		t.Fatalf("seeded owner grants = %d, want 0", ownerGrants)
	}
}

func TestPostgresPgStoreScoping(t *testing.T) {
	pool := rebuildDB(t, true)
	ctx := context.Background()
	store := &pgStore{pool}

	acme := idBy(t, pool, `SELECT id FROM tenants WHERE slug = 'acme'`)
	globex := idBy(t, pool, `SELECT id FROM tenants WHERE slug = 'globex'`)
	member := idBy(t, pool, `SELECT id FROM users WHERE email = 'member@acme.test'`)
	owner := idBy(t, pool, `SELECT id FROM users WHERE email = 'owner@acme.test'`)
	website := idBy(t, pool, `SELECT id FROM example_projects WHERE name = 'Website'`)

	slugs, err := store.RoleSlugs(ctx, acme, owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(slugs) != 1 || slugs[0] != "owner" {
		t.Fatalf("acme owner slugs = %v", slugs)
	}
	memberSlugs, err := store.RoleSlugs(ctx, acme, member)
	if err != nil {
		t.Fatal(err)
	}
	if len(memberSlugs) != 1 || memberSlugs[0] != "member" {
		t.Fatalf("acme member slugs = %v", memberSlugs)
	}
	if globexSlugs, err := store.RoleSlugs(ctx, globex, member); err != nil {
		t.Fatal(err)
	} else if len(globexSlugs) != 0 {
		t.Fatalf("acme member slugs on globex = %v, want none", globexSlugs)
	}

	codes, err := store.PermissionCodenames(ctx, acme, []string{"member"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(codes, "listProjects", "getProject", "listTasks", "listRoles") || contains(codes, "createProject") {
		t.Fatalf("member codenames = %v", codes)
	}

	ps, err := authz.Resolve(ctx, store, acme, owner, []string{"listProjects"}, authz.Options{WildcardRoleSlug: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if !ps.All() || !ps.Has("not-in-the-vocabulary") {
		t.Fatal("postgres owner must resolve as a wildcard")
	}

	if ok, err := store.IsMember(ctx, acme, idBy(t, pool, `SELECT id FROM users WHERE email = 'owner@globex.test'`)); err != nil || ok {
		t.Fatalf("globex owner IsMember(acme) = %v, %v; want false, nil", ok, err)
	}

	projects, err := store.ListProjects(ctx, acme)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 1 || projects[0].Name != "Website" || projects[0].WorkspaceID != acme {
		t.Fatalf("acme projects = %+v", projects)
	}
	if _, ok, err := store.GetProject(ctx, globex, website); err != nil || ok {
		t.Fatalf("globex GetProject(acme website) = %v, %v", ok, err)
	}
	if ok, err := store.DeleteProject(ctx, globex, website); err != nil || ok {
		t.Fatalf("cross-tenant delete = %v, %v", ok, err)
	}
	if _, ok, err := store.GetProject(ctx, acme, website); err != nil || !ok {
		t.Fatal("cross-tenant delete must not remove the acme project")
	}

	if err := store.CreateRole(ctx, acme, "auditor", "Auditor"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRole(ctx, globex, "auditor", "Auditor"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRole(ctx, acme, "auditor", "Again"); err == nil {
		t.Fatal("duplicate slug must fail")
	}
	if _, err := store.SetRolePermission(ctx, acme, "editor", "deleteProject", true); !errors.Is(err, errSystemRole) {
		t.Fatalf("system grant err = %v, want errSystemRole", err)
	}
	if ok, err := store.SetRolePermission(ctx, acme, "auditor", "createProject", true); err != nil || !ok {
		t.Fatalf("custom grant = %v, %v", ok, err)
	}
	if ok, err := store.SetRolePermission(ctx, globex, "auditor", "deleteProject", true); err != nil || !ok {
		t.Fatalf("globex custom grant = %v, %v", ok, err)
	}
	acmeCodes, err := store.PermissionCodenames(ctx, acme, []string{"auditor"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(acmeCodes, "createProject") || contains(acmeCodes, "deleteProject") {
		t.Fatalf("acme auditor codenames = %v", acmeCodes)
	}
	globexCodes, err := store.PermissionCodenames(ctx, globex, []string{"auditor"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(globexCodes, "deleteProject") || contains(globexCodes, "createProject") {
		t.Fatalf("globex auditor codenames = %v", globexCodes)
	}

	if ok, err := store.AssignRole(ctx, acme, member, "auditor"); err != nil || !ok {
		t.Fatalf("assign = %v, %v", ok, err)
	}
	var boundTenant int64
	if err := pool.QueryRow(ctx, `
		SELECT mr.tenant_id
		FROM membership_roles mr
		JOIN memberships m ON m.id = mr.membership_id
		JOIN roles r ON r.id = mr.role_id
		WHERE m.user_id = $1 AND r.slug = 'auditor'`, member).Scan(&boundTenant); err != nil {
		t.Fatal(err)
	}
	if boundTenant != acme {
		t.Fatalf("binding tenant = %d, want %d", boundTenant, acme)
	}
	slugs, err = store.RoleSlugs(ctx, acme, member)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(slugs, "auditor") || !contains(slugs, "member") {
		t.Fatalf("slugs after assign = %v", slugs)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE roles SET deleted_at = now()
		WHERE tenant_id = $1 AND slug = 'auditor' AND is_system = false`, acme); err != nil {
		t.Fatal(err)
	}
	slugs, err = store.RoleSlugs(ctx, acme, member)
	if err != nil {
		t.Fatal(err)
	}
	if contains(slugs, "auditor") {
		t.Fatalf("soft-deleted role still granted: %v", slugs)
	}

	if err := store.CreateRole(ctx, acme, "manager", "Manager"); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.AssignRole(ctx, acme, member, "manager"); err != nil || !ok {
		t.Fatalf("assign manager = %v, %v", ok, err)
	}
	if ok, err := store.UnassignRole(ctx, acme, member, "manager"); err != nil || !ok {
		t.Fatalf("unassign = %v, %v", ok, err)
	}
	slugs, err = store.RoleSlugs(ctx, acme, member)
	if err != nil {
		t.Fatal(err)
	}
	if contains(slugs, "manager") {
		t.Fatalf("unassign left the slug: %v", slugs)
	}
	if ok, err := store.UnassignRole(ctx, acme, member, "manager"); err != nil || ok {
		t.Fatalf("second unassign = %v, %v; want false, nil", ok, err)
	}

	if ok, err := store.DeleteProject(ctx, acme, website); err != nil || !ok {
		t.Fatalf("delete website = %v, %v", ok, err)
	}
	if got := mustCount(t, pool, `SELECT count(*) FROM example_tasks WHERE project_id = $1`, website); got != 0 {
		t.Fatalf("cascade left %d tasks", got)
	}
}

func TestPostgresHTTPAuthz(t *testing.T) {
	pool := rebuildDB(t, true)
	h := newServer(&pgStore{pool}).router()

	if got := do(t, h, "GET", "/health", "", "", nil).Code; got != http.StatusOK {
		t.Fatalf("health = %d, want 200", got)
	}
	if got := do(t, h, "GET", "/projects", "", "acme", nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("no session = %d, want 401", got)
	}
	if got := do(t, h, "GET", "/projects", "owner-globex", "acme", nil).Code; got != http.StatusNotFound {
		t.Fatalf("non-member = %d, want 404", got)
	}
	if got := do(t, h, "GET", "/projects", "member-acme", "acme", nil).Code; got != http.StatusOK {
		t.Fatalf("member list = %d, want 200", got)
	}
	if got := do(t, h, "POST", "/projects", "member-acme", "acme", map[string]string{"name": "N"}).Code; got != http.StatusForbidden {
		t.Fatalf("member create = %d, want 403", got)
	}
	if got := do(t, h, "POST", "/roles/editor/permissions", "owner-acme", "acme",
		map[string]any{"codename": "deleteProject", "allow": true}).Code; got != http.StatusForbidden {
		t.Fatalf("system grant = %d, want 403", got)
	}
	if got := do(t, h, "POST", "/roles", "owner-acme", "acme",
		map[string]string{"slug": "owner", "name": "Nope"}).Code; got != http.StatusConflict {
		t.Fatalf("reserved slug = %d, want 409", got)
	}

	website := idBy(t, pool, `SELECT id FROM example_projects WHERE name = 'Website'`)
	if got := do(t, h, "DELETE", fmt.Sprintf("/projects/%d", website), "owner-acme", "acme", nil).Code; got != http.StatusOK {
		t.Fatalf("owner delete = %d, want 200", got)
	}
	if got := do(t, h, "DELETE", "/projects/99999", "owner-acme", "acme", nil).Code; got != http.StatusNotFound {
		t.Fatalf("cached owner delete = %d, want 404 (gate passed, row missing)", got)
	}

	if got := do(t, h, "POST", "/roles", "owner-acme", "acme",
		map[string]string{"slug": "manager", "name": "Manager"}).Code; got != http.StatusCreated {
		t.Fatalf("createRole = %d, want 201", got)
	}
	if got := do(t, h, "POST", "/roles/manager/permissions", "owner-acme", "acme",
		map[string]any{"codename": "createProject", "allow": true}).Code; got != http.StatusOK {
		t.Fatalf("grant = %d, want 200", got)
	}
	member := idBy(t, pool, `SELECT id FROM users WHERE email = 'member@acme.test'`)
	if got := do(t, h, "POST", "/projects", "member-acme", "acme", map[string]string{"name": "Before"}).Code; got != http.StatusForbidden {
		t.Fatalf("pre-assign = %d, want 403", got)
	}
	if got := do(t, h, "POST", fmt.Sprintf("/members/%d/roles/manager", member), "owner-acme", "acme", nil).Code; got != http.StatusOK {
		t.Fatalf("assign = %d, want 200", got)
	}
	if got := do(t, h, "POST", "/projects", "member-acme", "acme", map[string]string{"name": "After"}).Code; got != http.StatusCreated {
		t.Fatalf("post-assign = %d, want 201", got)
	}
	if got := do(t, h, "DELETE", fmt.Sprintf("/members/%d/roles/manager", member), "owner-acme", "acme", nil).Code; got != http.StatusOK {
		t.Fatalf("unassign = %d, want 200", got)
	}
	if got := do(t, h, "POST", "/projects", "member-acme", "acme", map[string]string{"name": "Revoked"}).Code; got != http.StatusForbidden {
		t.Fatalf("post-revoke = %d, want 403", got)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func containsAll(ss []string, wants ...string) bool {
	for _, want := range wants {
		if !contains(ss, want) {
			return false
		}
	}
	return true
}
