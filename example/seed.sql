-- Copyright 2026 The authz Authors.
-- SPDX-License-Identifier: Apache-2.0
--
-- Example schema + demo data for the Projects & Tasks showcase. Runs after
-- the reference schema and the seed function (see docker-compose.yml).

CREATE TABLE example_tokens (
    token   TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE example_projects (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    owner_id   BIGINT NOT NULL REFERENCES users (id),
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE example_tasks (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES example_projects (id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    done       BOOLEAN NOT NULL DEFAULT false
);

-- Workspaces + users.
INSERT INTO tenants (slug, name) VALUES ('acme', 'Acme'), ('globex', 'Globex');
INSERT INTO users (email) VALUES
    ('owner@acme.test'), ('editor@acme.test'), ('member@acme.test'), ('owner@globex.test');

-- Bearer tokens (identity stub).
INSERT INTO example_tokens (token, user_id)
SELECT t.token, u.id
FROM (VALUES
    ('owner-acme',   'owner@acme.test'),
    ('editor-acme',  'editor@acme.test'),
    ('member-acme',  'member@acme.test'),
    ('owner-globex', 'owner@globex.test')
) AS t(token, email)
JOIN users u ON u.email = t.email;

-- Memberships (user × workspace).
INSERT INTO memberships (tenant_id, user_id)
SELECT t.id, u.id
FROM (VALUES
    ('acme',   'owner@acme.test'),
    ('acme',   'editor@acme.test'),
    ('acme',   'member@acme.test'),
    ('globex', 'owner@globex.test')
) AS m(workspace, email)
JOIN tenants t ON t.slug = m.workspace
JOIN users u ON u.email = m.email;

-- System roles + permission matrix. Include the wildcard role with an empty
-- list so its row exists (the wildcard holds no permission rows).
SELECT seed_role_permissions('{
  "owner":  [],
  "editor": ["listProjects","createProject","getProject","listTasks","createTask","completeTask","listRoles"],
  "member": ["listProjects","getProject","listTasks","listRoles"]
}');

-- Bind memberships to roles.
INSERT INTO membership_roles (membership_id, role_id)
SELECT m.id, r.id
FROM (VALUES
    ('acme',   'owner@acme.test',   'owner'),
    ('acme',   'editor@acme.test',  'editor'),
    ('acme',   'member@acme.test',  'member'),
    ('globex', 'owner@globex.test', 'owner')
) AS b(workspace, email, role_slug)
JOIN tenants t ON t.slug = b.workspace
JOIN users u ON u.email = b.email
JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
JOIN roles r ON r.tenant_id = t.id AND r.slug = b.role_slug;

-- Demo resources.
INSERT INTO example_projects (tenant_id, owner_id, name)
SELECT t.id, u.id, p.name
FROM (VALUES ('acme', 'owner@acme.test', 'Website'), ('globex', 'owner@globex.test', 'Mobile')) AS p(workspace, email, name)
JOIN tenants t ON t.slug = p.workspace
JOIN users u ON u.email = p.email;

INSERT INTO example_tasks (project_id, title)
SELECT p.id, x.title
FROM (VALUES ('Website', 'Draft spec'), ('Website', 'Review')) AS x(project, title)
JOIN example_projects p ON p.name = x.project;
