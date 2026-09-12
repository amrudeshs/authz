// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import "context"

// errSystemRole is returned when a write targets an immutable system role.
var errSystemRole = errorString("system roles are immutable")

type errorString string

func (e errorString) Error() string { return string(e) }

// Domain types. A workspace is the tenant; members hold roles; projects and
// tasks are the capability-gated resources.

type Workspace struct {
	ID   int64
	Slug string
	Name string
}

type User struct {
	ID    int64
	Email string
}

type Project struct {
	ID          int64
	WorkspaceID int64
	OwnerID     int64
	Name        string
}

type Task struct {
	ID        int64
	ProjectID int64
	Title     string
	Done      bool
}

type RoleInfo struct {
	Slug        string   `json:"slug"`
	System      bool     `json:"system"`
	Permissions []string `json:"permissions"`
}

// Store is the example's persistence. It also satisfies authz.Resolver
// (RoleSlugs + PermissionCodenames), so the same object backs resolution.
type Store interface {
	UserByToken(ctx context.Context, token string) (User, bool, error)
	WorkspaceBySlug(ctx context.Context, slug string) (Workspace, bool, error)
	IsMember(ctx context.Context, workspaceID, userID int64) (bool, error)

	RoleSlugs(ctx context.Context, workspaceID, userID int64) ([]string, error)
	PermissionCodenames(ctx context.Context, workspaceID int64, slugs []string) ([]string, error)

	ListProjects(ctx context.Context, workspaceID int64) ([]Project, error)
	CreateProject(ctx context.Context, workspaceID, ownerID int64, name string) (Project, error)
	GetProject(ctx context.Context, workspaceID, id int64) (Project, bool, error)
	DeleteProject(ctx context.Context, workspaceID, id int64) (bool, error)
	ListTasks(ctx context.Context, workspaceID, projectID int64) ([]Task, error)
	CreateTask(ctx context.Context, workspaceID, projectID int64, title string) (Task, bool, error)
	CompleteTask(ctx context.Context, workspaceID, taskID int64) (bool, error)
	ListRoles(ctx context.Context, workspaceID int64) ([]RoleInfo, error)
	CreateRole(ctx context.Context, workspaceID int64, slug, name string) error
	SetRolePermission(ctx context.Context, workspaceID int64, slug, codename string, allow bool) (bool, error)
	AssignRole(ctx context.Context, workspaceID, userID int64, slug string) (bool, error)
}
