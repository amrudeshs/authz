-- Copyright 2026 The authz Authors.
-- SPDX-License-Identifier: Apache-2.0
--
-- Reference schema for the authz function-level layer (generic — no host
-- domain terminology). Apply once against a clean database.
--
-- Tenants, users and memberships are the host's own tables; this file ships
-- minimal stand-ins so the reference schema runs standalone. Rename them to
-- the host's tables if they already exist (the authz tables only reference
-- tenants(id) and memberships(id)).

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

-- A membership is the (user × tenant) row; roles bind to it, so roles are
-- tenant-scoped for free and meaningless outside a tenant.
CREATE TABLE memberships (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id)
);

-- Roles are per-tenant data bundling permission codenames. System roles are
-- immutable by construction (is_system plus the guard in every write path).
-- Soft delete keeps history reconstructible; a soft-deleted role grants
-- nothing (the resolver filters deleted_at).
CREATE TABLE roles (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    is_system  BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX roles_tenant_slug_idx
    ON roles (tenant_id, slug) WHERE deleted_at IS NULL;

-- The codenames a role grants. Unknown codenames are inert (they match no
-- current vocabulary entry) — fail closed, swept at codegen time.
CREATE TABLE role_permissions (
    role_id             BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_codename TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_codename)
);

-- Membership-scoped role bindings (a user holds roles through a membership).
CREATE TABLE membership_roles (
    membership_id BIGINT NOT NULL REFERENCES memberships (id) ON DELETE CASCADE,
    role_id       BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (membership_id, role_id)
);

CREATE INDEX membership_roles_role_idx ON membership_roles (role_id);
