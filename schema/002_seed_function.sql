-- Copyright 2026 The authz Authors.
-- SPDX-License-Identifier: Apache-2.0
--
-- Idempotent, re-invocable seeding of the system role → codename matrix.
--
-- The matrix is host data: pass it as a JSON object mapping role slug to an
-- array of codenames, e.g.
--
--   SELECT seed_role_permissions('{
--     "owner":  ["project.create", "project.read", "project.delete"],
--     "editor": ["project.create", "project.read"],
--     "member": ["project.read"]
--   }');
--
-- Running it again resets the system roles' permissions to exactly the
-- matrix (so it is safe after test truncations or a vocabulary change).
-- Custom roles are never touched. The wildcard admin role holds no rows.

CREATE OR REPLACE FUNCTION seed_role_permissions(seed jsonb)
RETURNS void AS $$
BEGIN
    -- 1. Ensure an active system-role row per tenant for every seeded slug.
    INSERT INTO roles (tenant_id, slug, name, is_system)
    SELECT t.id, s.slug, initcap(s.slug), true
    FROM tenants t
    CROSS JOIN LATERAL jsonb_object_keys(seed) AS s(slug)
    WHERE NOT EXISTS (
        SELECT 1 FROM roles r
        WHERE r.tenant_id = t.id AND r.slug = s.slug AND r.deleted_at IS NULL
    );

    -- 2. Reset the seeded system roles to exactly the matrix.
    DELETE FROM role_permissions rp
    USING roles r
    WHERE rp.role_id = r.id
      AND r.is_system
      AND r.slug IN (SELECT jsonb_object_keys(seed));

    INSERT INTO role_permissions (role_id, permission_codename)
    SELECT r.id, c.codename
    FROM roles r
    CROSS JOIN LATERAL jsonb_array_elements_text(seed -> r.slug) AS c(codename)
    WHERE r.is_system
      AND r.deleted_at IS NULL
      AND seed ? r.slug;
END;
$$ LANGUAGE plpgsql;
