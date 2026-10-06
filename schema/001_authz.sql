-- Copyright 2026 The authz Authors.
-- SPDX-License-Identifier: Apache-2.0
--
-- Reference schema for the authz function-level layer (generic — no host
-- domain terminology). Apply once against a clean database.
--
-- Tenants, users and memberships are the host's own tables; this file ships
-- minimal stand-ins so the reference schema runs standalone. Rename them to
-- the host's tables if they already exist (the authz tables only reference
-- tenants(id) and memberships(id, tenant_id)).

CREATE TABLE tenants (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Host identity stand-in. The authz layer only needs a stable user id.
CREATE TABLE users (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A membership is the (user × tenant) row; roles bind to it. The extra
-- unique key on (id, tenant_id) exists so membership_roles can reference
-- both columns and a role from another tenant cannot be attached.
CREATE TABLE memberships (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id),
    UNIQUE (id, tenant_id)
);

-- Roles are per-tenant data bundling permission codenames. is_system marks
-- a role whose grants the seed function owns. It is not, by itself, a write
-- guard: schema/002_seed_function.sql installs the trigger that rejects
-- permission changes on these rows unless seed_role_permissions is running.
-- Soft delete keeps history; a soft-deleted role grants nothing only if the
-- resolver filters deleted_at (the reference query does). The core cannot
-- see a violation. Nothing in this schema sets deleted_at — that UPDATE is
-- the host's.
CREATE TABLE roles (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    is_system  BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id)
);
CREATE UNIQUE INDEX roles_tenant_slug_idx
    ON roles (tenant_id, slug) WHERE deleted_at IS NULL;

-- The codenames a role grants. Unknown codenames match nothing at check
-- time (string equality against the codename the route asks for). They are
-- not swept by codegen; codegen never connects to the database.
CREATE TABLE role_permissions (
    role_id             BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_codename TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_codename)
);

-- Membership-scoped role bindings. tenant_id must match both the membership
-- and the role, so a binding cannot point at another tenant's role. A
-- wildcard decision is slug equality; without this constraint a foreign
-- "owner" slug would grant the caller's whole vocabulary.
CREATE TABLE membership_roles (
    membership_id BIGINT NOT NULL,
    role_id       BIGINT NOT NULL,
    tenant_id     BIGINT NOT NULL,
    PRIMARY KEY (membership_id, role_id),
    FOREIGN KEY (membership_id, tenant_id) REFERENCES memberships (id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id, tenant_id) REFERENCES roles (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX membership_roles_role_idx ON membership_roles (role_id);
