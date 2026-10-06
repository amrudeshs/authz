-- Copyright 2026 The authz Authors.
-- SPDX-License-Identifier: Apache-2.0
--
-- Idempotent, re-invocable seeding of the system role → codename matrix.
--
-- The matrix is host data: pass it as a JSON object mapping role slug to an
-- array of codenames, e.g.
--
--   SELECT seed_role_permissions('{
--     "owner":  [],
--     "editor": ["project.create", "project.read"],
--     "member": ["project.read"]
--   }');
--
-- Running it again replaces the grants of every active system role with
-- exactly the matrix. Slugs absent from the matrix keep their role row (so
-- existing memberships still resolve) but lose their grants. Custom roles
-- are never touched. Soft-deleted system roles are left alone, including
-- their permission history. Include the wildcard role with an empty array
-- so its row exists for membership binding; the wildcard grant itself is a
-- process option (Options.WildcardRoleSlug), not a row in role_permissions.
--
-- The matrix is stored. A later INSERT into tenants re-runs the function, so
-- a tenant created after the first seed gets the same system roles. An
-- insert that happens before any seed is a no-op until the host calls the
-- function.
--
-- search_path is pinned so unqualified names cannot follow the caller's
-- path. The function is invoker-rights: EXECUTE for PUBLIC is the PostgreSQL
-- default and is not a privilege escalation; the caller still needs to be
-- able to write the tables. System-role permission writes from anywhere else
-- are rejected unless this function has set the transaction-local
-- authz.seeding flag. A role that can SET that flag can bypass the trigger;
-- application code should call the function instead of setting it.

CREATE TABLE IF NOT EXISTS authz_role_seed (
    id   INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    seed JSONB NOT NULL
);

CREATE OR REPLACE FUNCTION seed_role_permissions(seed jsonb)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- Transaction-local. The permission-write trigger allows this function
    -- through and rejects every other writer.
    PERFORM set_config('authz.seeding', 'on', true);

    INSERT INTO authz_role_seed (id, seed) VALUES (1, seed)
    ON CONFLICT (id) DO UPDATE SET seed = EXCLUDED.seed;

    -- 1. Ensure an active system-role row per tenant for every seeded slug.
    INSERT INTO roles (tenant_id, slug, name, is_system)
    SELECT t.id, s.slug, initcap(s.slug), true
    FROM tenants t
    CROSS JOIN LATERAL jsonb_object_keys(seed) AS s(slug)
    WHERE NOT EXISTS (
        SELECT 1 FROM roles r
        WHERE r.tenant_id = t.id AND r.slug = s.slug AND r.deleted_at IS NULL
    );

    -- 2. Active system-role grants become exactly the matrix. Slugs no
    -- longer in the payload lose their grants; their role row stays.
    DELETE FROM role_permissions rp
    USING roles r
    WHERE rp.role_id = r.id
      AND r.is_system
      AND r.deleted_at IS NULL;

    INSERT INTO role_permissions (role_id, permission_codename)
    SELECT r.id, c.codename
    FROM roles r
    CROSS JOIN LATERAL jsonb_array_elements_text(seed -> r.slug) AS c(codename)
    WHERE r.is_system
      AND r.deleted_at IS NULL
      AND seed ? r.slug;
END;
$$;

-- Reject permission changes on system roles unless seed_role_permissions is
-- the writer. Owners of the table can still disable the trigger; the point
-- is that ordinary SQL and the application write path cannot.
CREATE OR REPLACE FUNCTION authz_reject_system_role_permission_write()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    rid bigint;
    system boolean;
BEGIN
    IF current_setting('authz.seeding', true) = 'on' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        rid := OLD.role_id;
    ELSE
        rid := NEW.role_id;
    END IF;
    SELECT is_system INTO system FROM roles WHERE id = rid;
    IF system THEN
        RAISE EXCEPTION 'system role permissions are immutable; call seed_role_permissions'
            USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS role_permissions_system_guard ON role_permissions;
CREATE TRIGGER role_permissions_system_guard
    BEFORE INSERT OR UPDATE OR DELETE ON role_permissions
    FOR EACH ROW
    EXECUTE FUNCTION authz_reject_system_role_permission_write();

-- Reject updates and deletes of system role rows outside the seed function.
-- Inserting a system role is allowed: that is how the seed creates them, and
-- a direct insert of is_system = true is the same shape. Flipping the flag
-- or deleting the row is not.
CREATE OR REPLACE FUNCTION authz_reject_system_role_row_write()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF current_setting('authz.seeding', true) = 'on' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' AND OLD.is_system THEN
        RAISE EXCEPTION 'system roles cannot be deleted; call seed_role_permissions'
            USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.is_system THEN
        RAISE EXCEPTION 'system roles cannot be updated; call seed_role_permissions'
            USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS roles_system_guard ON roles;
CREATE TRIGGER roles_system_guard
    BEFORE UPDATE OR DELETE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION authz_reject_system_role_row_write();

-- After the matrix has been stored, a new tenant gets the same system roles.
CREATE OR REPLACE FUNCTION authz_seed_new_tenant()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    matrix jsonb;
BEGIN
    SELECT seed INTO matrix FROM authz_role_seed WHERE id = 1;
    IF matrix IS NULL THEN
        RETURN NULL;
    END IF;
    PERFORM seed_role_permissions(matrix);
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS tenants_seed_roles ON tenants;
CREATE TRIGGER tenants_seed_roles
    AFTER INSERT ON tenants
    FOR EACH STATEMENT
    EXECUTE FUNCTION authz_seed_new_tenant();
