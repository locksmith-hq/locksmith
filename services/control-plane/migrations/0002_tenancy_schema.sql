-- S1 design decision 6 (A0-4, A0-5, A0-6, A0-9): tenant tables owned by locksmith_owner, keyed by
-- UUIDv7, each carrying org_id under FORCE ROW LEVEL SECURITY. Children point at their parents
-- through composite foreign keys that include org_id, so a row can never reference another
-- org's parent (foreign-key checks ignore RLS, so a plain parent_id FK would allow it).
--
-- Secrets hold metadata only. There is no value column anywhere; S2 adds secret_versions.
SET LOCAL ROLE locksmith_owner;

-- After a transaction-local set_config commits, the custom GUC stays defined in that session
-- with the value '' (not NULL), so NULLIF is required: ''::uuid would raise instead of matching
-- nothing. With no org bound, every table reads as empty and rejects writes.
CREATE FUNCTION current_org_id() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT NULLIF(current_setting('app.org_id', true), '')::uuid $$;

CREATE TABLE orgs (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    name       text        NOT NULL CHECK (btrim(name) <> ''),
    -- A0-9: every org has a region from day one.
    region     text        NOT NULL DEFAULT 'us-east-1',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id      uuid        NOT NULL REFERENCES orgs (id),
    name        text        NOT NULL CHECK (btrim(name) <> ''),
    description text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    -- Target of the children's composite FKs; also the keyset-pagination index.
    UNIQUE (org_id, id),
    UNIQUE (org_id, name)
);

CREATE TABLE environments (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id      uuid        NOT NULL,
    project_id  uuid        NOT NULL,
    name        text        NOT NULL CHECK (btrim(name) <> ''),
    description text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    UNIQUE (org_id, project_id, id),
    -- Unique keys lead with org_id: a key without it would let one org probe another org's
    -- names (a duplicate-key error before the foreign-key check).
    UNIQUE (org_id, project_id, name)
);

CREATE TABLE secrets (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id         uuid        NOT NULL,
    project_id     uuid        NOT NULL,
    environment_id uuid        NOT NULL,
    name           text        NOT NULL CHECK (btrim(name) <> ''),
    description    text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    -- The environment must belong to the same org and the same project.
    FOREIGN KEY (org_id, project_id, environment_id)
        REFERENCES environments (org_id, project_id, id),
    UNIQUE (org_id, project_id, environment_id, name)
);
CREATE INDEX secrets_list_idx ON secrets (org_id, project_id, environment_id, id);

ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE orgs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON orgs
    USING (id = current_org_id())
    WITH CHECK (id = current_org_id());

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON projects
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON environments
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secrets
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

REVOKE ALL ON FUNCTION current_org_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION current_org_id() TO locksmith_app;
-- Orgs are created (decision 7) and renamed, never deleted, in S1.
GRANT SELECT, INSERT, UPDATE ON orgs TO locksmith_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON projects, environments, secrets TO locksmith_app;

-- sqlx records the migration in _sqlx_migrations in this same transaction, as the login role,
-- so drop back to it before the migration ends.
RESET ROLE;
