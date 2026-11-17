-- A0 decisions 4-7: a tenant table owned by a0_owner, keyed by UUIDv7, with org_id, FORCE RLS
-- and a policy on the transaction-local setting app.org_id.
SET LOCAL ROLE a0_owner;

CREATE TABLE secrets (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id     uuid        NOT NULL,
    name       text        NOT NULL,
    -- Versioned ciphertext header blob (design decision 7); never plaintext.
    ciphertext bytea,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX secrets_org_id_idx ON secrets (org_id);

ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;

-- After a transaction-local set_config commits, the custom GUC stays defined in that session
-- with the value '' (not NULL), so NULLIF is required: ''::uuid would raise instead of
-- matching nothing. Unset context therefore sees zero rows and cannot insert.
CREATE POLICY tenant_isolation ON secrets
    USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON secrets TO a0_app;

-- sqlx records the migration in _sqlx_migrations (owned by the migrating login) in this same
-- transaction, so drop back to it before the migration ends.
RESET ROLE;
