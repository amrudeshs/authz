// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// memStore is an in-memory Store used by tests (and by `go run` when no
// DATABASE_URL is set). It seeds the same demo data as the SQL seed.
type memStore struct {
	mu sync.Mutex

	users    map[int64]User
	tokens   map[string]int64
	spaces   map[int64]Workspace
	bySlug   map[string]int64
	members  map[int64]map[int64]bool     // workspace -> user -> member
	userRole map[int64]map[int64][]string // workspace -> user -> slugs
	roles    map[int64]map[string]*memRole
	projects map[int64]Project
	tasks    map[int64]Task
	nextProj int64
	nextTask int64
}

type memRole struct {
	name   string
	system bool
	perms  map[string]bool
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func newMemStore() *memStore {
	s := &memStore{
		users:    map[int64]User{1: {1, "owner@acme.test"}, 2: {2, "editor@acme.test"}, 3: {3, "member@acme.test"}, 4: {4, "owner@globex.test"}},
		tokens:   map[string]int64{"owner-acme": 1, "editor-acme": 2, "member-acme": 3, "owner-globex": 4},
		spaces:   map[int64]Workspace{1: {1, "acme", "Acme"}, 2: {2, "globex", "Globex"}},
		bySlug:   map[string]int64{"acme": 1, "globex": 2},
		members:  map[int64]map[int64]bool{1: {1: true, 2: true, 3: true}, 2: {4: true}},
		userRole: map[int64]map[int64][]string{1: {1: {"owner"}, 2: {"editor"}, 3: {"member"}}, 2: {4: {"owner"}}},
		roles:    map[int64]map[string]*memRole{},
		projects: map[int64]Project{1: {1, 1, 1, "Website"}, 2: {2, 2, 4, "Mobile"}},
		tasks:    map[int64]Task{1: {1, 1, "Draft spec", false}, 2: {2, 1, "Review", false}},
		nextProj: 3,
		nextTask: 3,
	}
	for _, ws := range []int64{1, 2} {
		s.roles[ws] = map[string]*memRole{}
		for slug, codenames := range RoleSeed {
			p := map[string]bool{}
			for _, c := range codenames {
				p[c] = true
			}
			s.roles[ws][slug] = &memRole{name: titleCase(slug), system: true, perms: p}
		}
	}
	return s
}

func (s *memStore) UserByToken(_ context.Context, token string) (User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.tokens[token]
	return s.users[id], ok, nil
}

func (s *memStore) WorkspaceBySlug(_ context.Context, slug string) (Workspace, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.bySlug[slug]
	return s.spaces[id], ok, nil
}

func (s *memStore) IsMember(_ context.Context, workspaceID, userID int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.members[workspaceID][userID], nil
}

func (s *memStore) RoleSlugs(_ context.Context, workspaceID, userID int64) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.userRole[workspaceID][userID]...), nil
}

func (s *memStore) PermissionCodenames(_ context.Context, workspaceID int64, slugs []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	for _, slug := range slugs {
		if r, ok := s.roles[workspaceID][slug]; ok {
			for c := range r.perms {
				seen[c] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

func (s *memStore) ListProjects(_ context.Context, workspaceID int64) ([]Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Project
	for _, p := range s.projects {
		if p.WorkspaceID == workspaceID {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *memStore) CreateProject(_ context.Context, workspaceID, ownerID int64, name string) (Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := Project{ID: s.nextProj, WorkspaceID: workspaceID, OwnerID: ownerID, Name: name}
	s.nextProj++
	s.projects[p.ID] = p
	return p, nil
}

func (s *memStore) GetProject(_ context.Context, workspaceID, id int64) (Project, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[id]
	return p, ok && p.WorkspaceID == workspaceID, nil
}

func (s *memStore) DeleteProject(_ context.Context, workspaceID, id int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[id]
	if !ok || p.WorkspaceID != workspaceID {
		return false, nil
	}
	delete(s.projects, id)
	for tid, t := range s.tasks {
		if t.ProjectID == id {
			delete(s.tasks, tid)
		}
	}
	return true, nil
}

func (s *memStore) ListTasks(_ context.Context, workspaceID, projectID int64) ([]Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[projectID]
	if !ok || p.WorkspaceID != workspaceID {
		return nil, nil
	}
	var out []Task
	for _, t := range s.tasks {
		if t.ProjectID == projectID {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *memStore) CreateTask(_ context.Context, workspaceID, projectID int64, title string) (Task, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[projectID]
	if !ok || p.WorkspaceID != workspaceID {
		return Task{}, false, nil
	}
	t := Task{ID: s.nextTask, ProjectID: projectID, Title: title}
	s.nextTask++
	s.tasks[t.ID] = t
	return t, true, nil
}

func (s *memStore) CompleteTask(_ context.Context, workspaceID, taskID int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[taskID]
	if !ok {
		return false, nil
	}
	if p, ok := s.projects[t.ProjectID]; !ok || p.WorkspaceID != workspaceID {
		return false, nil
	}
	t.Done = true
	s.tasks[taskID] = t
	return true, nil
}

func (s *memStore) ListRoles(_ context.Context, workspaceID int64) ([]RoleInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []RoleInfo
	for slug, r := range s.roles[workspaceID] {
		perms := make([]string, 0, len(r.perms))
		for c := range r.perms {
			perms = append(perms, c)
		}
		sort.Strings(perms)
		out = append(out, RoleInfo{Slug: slug, System: r.system, Permissions: perms})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (s *memStore) CreateRole(_ context.Context, workspaceID int64, slug, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.roles[workspaceID][slug]; exists {
		return fmt.Errorf("role %q already exists", slug)
	}
	s.roles[workspaceID][slug] = &memRole{name: name, perms: map[string]bool{}}
	return nil
}

func (s *memStore) SetRolePermission(_ context.Context, workspaceID int64, slug, codename string, allow bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[workspaceID][slug]
	if !ok {
		return false, nil // unknown role
	}
	if r.system {
		return false, errSystemRole // immutable
	}
	if allow {
		r.perms[codename] = true
	} else {
		delete(r.perms, codename)
	}
	return true, nil
}

func (s *memStore) AssignRole(_ context.Context, workspaceID, userID int64, slug string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.members[workspaceID][userID] {
		return false, nil
	}
	if _, ok := s.roles[workspaceID][slug]; !ok {
		return false, nil
	}
	cur := s.userRole[workspaceID][userID]
	for _, s2 := range cur {
		if s2 == slug {
			return true, nil
		}
	}
	s.userRole[workspaceID][userID] = append(cur, slug)
	return true, nil
}

func (s *memStore) UnassignRole(_ context.Context, workspaceID, userID int64, slug string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.members[workspaceID][userID] {
		return false, nil
	}
	if _, ok := s.roles[workspaceID][slug]; !ok {
		return false, nil
	}
	cur := s.userRole[workspaceID][userID]
	next := make([]string, 0, len(cur))
	found := false
	for _, held := range cur {
		if held == slug {
			found = true
			continue
		}
		next = append(next, held)
	}
	if !found {
		return false, nil
	}
	s.userRole[workspaceID][userID] = next
	return true, nil
}
