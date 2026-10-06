// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgStore is the Postgres-backed Store used by the running example. It also
// implements authz.Resolver, so role/permission resolution reads the tables
// the reference schema defines.
type pgStore struct{ pool *pgxpool.Pool }

func (s *pgStore) UserByToken(ctx context.Context, token string) (User, bool, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT u.id, u.email FROM example_tokens t JOIN users u ON u.id = t.user_id WHERE t.token = $1`,
		token).Scan(&u.ID, &u.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, false, nil
	}
	return u, err == nil, err
}

func (s *pgStore) WorkspaceBySlug(ctx context.Context, slug string) (Workspace, bool, error) {
	var w Workspace
	err := s.pool.QueryRow(ctx,
		`SELECT id, slug, name FROM tenants WHERE slug = $1`, slug).Scan(&w.ID, &w.Slug, &w.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return Workspace{}, false, nil
	}
	return w, err == nil, err
}

func (s *pgStore) IsMember(ctx context.Context, workspaceID, userID int64) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM memberships WHERE tenant_id = $1 AND user_id = $2)`,
		workspaceID, userID).Scan(&ok)
	return ok, err
}

func (s *pgStore) RoleSlugs(ctx context.Context, workspaceID, userID int64) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.slug
		FROM memberships m
		JOIN membership_roles mr ON mr.membership_id = m.id
		JOIN roles r ON r.id = mr.role_id AND r.tenant_id = mr.tenant_id
		WHERE m.tenant_id = $1 AND m.user_id = $2
		  AND mr.tenant_id = m.tenant_id
		  AND r.deleted_at IS NULL
		ORDER BY r.slug`, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectStrings(rows)
}

func (s *pgStore) PermissionCodenames(ctx context.Context, workspaceID int64, slugs []string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT rp.permission_codename
		FROM roles r
		JOIN role_permissions rp ON rp.role_id = r.id
		WHERE r.tenant_id = $1 AND r.slug = ANY($2) AND r.deleted_at IS NULL
		ORDER BY rp.permission_codename`, workspaceID, slugs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectStrings(rows)
}

func (s *pgStore) ListProjects(ctx context.Context, workspaceID int64) ([]Project, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, owner_id, name FROM example_projects WHERE tenant_id = $1 ORDER BY id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.WorkspaceID, &p.OwnerID, &p.Name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *pgStore) CreateProject(ctx context.Context, workspaceID, ownerID int64, name string) (Project, error) {
	var p Project
	err := s.pool.QueryRow(ctx,
		`INSERT INTO example_projects (tenant_id, owner_id, name) VALUES ($1, $2, $3)
		 RETURNING id, tenant_id, owner_id, name`, workspaceID, ownerID, name).
		Scan(&p.ID, &p.WorkspaceID, &p.OwnerID, &p.Name)
	return p, err
}

func (s *pgStore) GetProject(ctx context.Context, workspaceID, id int64) (Project, bool, error) {
	var p Project
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, owner_id, name FROM example_projects WHERE tenant_id = $1 AND id = $2`,
		workspaceID, id).Scan(&p.ID, &p.WorkspaceID, &p.OwnerID, &p.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, false, nil
	}
	return p, err == nil, err
}

func (s *pgStore) DeleteProject(ctx context.Context, workspaceID, id int64) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM example_projects WHERE tenant_id = $1 AND id = $2`, workspaceID, id)
	return err == nil && tag.RowsAffected() > 0, err
}

func (s *pgStore) ListTasks(ctx context.Context, workspaceID, projectID int64) ([]Task, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.project_id, t.title, t.done
		FROM example_tasks t
		JOIN example_projects p ON p.id = t.project_id
		WHERE p.tenant_id = $1 AND t.project_id = $2
		ORDER BY t.id`, workspaceID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.Title, &t.Done); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *pgStore) CreateTask(ctx context.Context, workspaceID, projectID int64, title string) (Task, bool, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM example_projects WHERE tenant_id = $1 AND id = $2)`,
		workspaceID, projectID).Scan(&exists); err != nil {
		return Task{}, false, err
	}
	if !exists {
		return Task{}, false, nil
	}
	var t Task
	err := s.pool.QueryRow(ctx,
		`INSERT INTO example_tasks (project_id, title) VALUES ($1, $2)
		 RETURNING id, project_id, title, done`, projectID, title).
		Scan(&t.ID, &t.ProjectID, &t.Title, &t.Done)
	return t, err == nil, err
}

func (s *pgStore) CompleteTask(ctx context.Context, workspaceID, taskID int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE example_tasks t SET done = true
		FROM example_projects p
		WHERE t.id = $2 AND t.project_id = p.id AND p.tenant_id = $1`, workspaceID, taskID)
	return err == nil && tag.RowsAffected() > 0, err
}

func (s *pgStore) ListRoles(ctx context.Context, workspaceID int64) ([]RoleInfo, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.slug, r.is_system,
		       COALESCE(array_agg(rp.permission_codename ORDER BY rp.permission_codename)
		                FILTER (WHERE rp.permission_codename IS NOT NULL), '{}') AS perms
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		WHERE r.tenant_id = $1 AND r.deleted_at IS NULL
		GROUP BY r.id, r.slug, r.is_system
		ORDER BY r.slug`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RoleInfo
	for rows.Next() {
		var ri RoleInfo
		if err := rows.Scan(&ri.Slug, &ri.System, &ri.Permissions); err != nil {
			return nil, err
		}
		out = append(out, ri)
	}
	return out, rows.Err()
}

func (s *pgStore) CreateRole(ctx context.Context, workspaceID int64, slug, name string) error {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO roles (tenant_id, slug, name, is_system) VALUES ($1, $2, $3, false)
		 ON CONFLICT DO NOTHING`, workspaceID, slug, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("role %q already exists", slug)
	}
	return nil
}

func (s *pgStore) SetRolePermission(ctx context.Context, workspaceID int64, slug, codename string, allow bool) (bool, error) {
	var roleID int64
	var system bool
	err := s.pool.QueryRow(ctx,
		`SELECT id, is_system FROM roles WHERE tenant_id = $1 AND slug = $2 AND deleted_at IS NULL`,
		workspaceID, slug).Scan(&roleID, &system)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if system {
		return false, errSystemRole
	}
	if allow {
		tag, execErr := s.pool.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_codename)
			SELECT r.id, $2 FROM roles r
			WHERE r.id = $1 AND r.tenant_id = $3 AND r.is_system = false AND r.deleted_at IS NULL
			ON CONFLICT DO NOTHING`, roleID, codename, workspaceID)
		if execErr != nil {
			return false, execErr
		}
		if tag.RowsAffected() == 0 {
			// The row already existed, or the role became a system role
			// between the read and the write. Re-read so a system role is
			// not reported as a successful no-op.
			var system bool
			err = s.pool.QueryRow(ctx,
				`SELECT is_system FROM roles WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
				roleID, workspaceID).Scan(&system)
			if err != nil {
				return false, err
			}
			if system {
				return false, errSystemRole
			}
		}
		return true, nil
	}
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM role_permissions rp
		USING roles r
		WHERE rp.role_id = r.id AND r.id = $1 AND r.tenant_id = $3
		  AND r.is_system = false AND rp.permission_codename = $2`, roleID, codename, workspaceID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		var system bool
		err = s.pool.QueryRow(ctx,
			`SELECT is_system FROM roles WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
			roleID, workspaceID).Scan(&system)
		if err != nil {
			return false, err
		}
		if system {
			return false, errSystemRole
		}
	}
	return true, nil
}

func (s *pgStore) AssignRole(ctx context.Context, workspaceID, userID int64, slug string) (bool, error) {
	var membershipID, roleID int64
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM memberships WHERE tenant_id = $1 AND user_id = $2`, workspaceID, userID).Scan(&membershipID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = s.pool.QueryRow(ctx,
		`SELECT id FROM roles WHERE tenant_id = $1 AND slug = $2 AND deleted_at IS NULL`, workspaceID, slug).Scan(&roleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO membership_roles (membership_id, role_id, tenant_id) VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		membershipID, roleID, workspaceID)
	return err == nil, err
}

func (s *pgStore) UnassignRole(ctx context.Context, workspaceID, userID int64, slug string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM membership_roles mr
		USING memberships m, roles r
		WHERE mr.membership_id = m.id
		  AND mr.role_id = r.id
		  AND mr.tenant_id = m.tenant_id
		  AND r.tenant_id = m.tenant_id
		  AND m.tenant_id = $1 AND m.user_id = $2
		  AND r.slug = $3 AND r.deleted_at IS NULL`, workspaceID, userID, slug)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func collectStrings(rows pgx.Rows) ([]string, error) {
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
