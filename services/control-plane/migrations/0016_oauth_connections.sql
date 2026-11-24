-- C1 design "Data model" and decisions 6, 7, 8, 10: a person's OAuth connections.
--
-- Third-party OAuth tokens are bearer credentials, so their ciphertext is reachable only by the
-- gateway's own role. `locksmith_gateway` is created like `locksmith_app` in 0001_roles.sql
-- (idempotent; a deployment may pre-create it with a real password; the dev-only password below
-- is listed with the compose credentials in infra/compose/.env.example). It is neither table
-- owner, superuser nor BYPASSRLS.
--
-- Privileges:
--   oauth_token_material  gateway only (locksmith_app has no privilege at all: a query fails)
--   oauth_flows           gateway only
--   oauth_connections     gateway writes, app reads (no token, code or verifier column)
--   oauth_providers       gateway writes, app reads
--   oauth_connection_grants  app writes (the person's own connections), gateway reads
--
-- Every table sits under FORCE ROW LEVEL SECURITY by org (A0-4, A0-5).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'locksmith_gateway') THEN
        BEGIN
            CREATE ROLE locksmith_gateway LOGIN PASSWORD 'locksmith-gateway-dev-only'
                NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;
    IF NOT has_schema_privilege('locksmith_gateway', 'public', 'USAGE') THEN
        GRANT USAGE ON SCHEMA public TO locksmith_gateway;
    END IF;
END
$$;

SET LOCAL ROLE locksmith_owner;

-- The gateway's enabled providers, published at startup (decision 9). Never a client secret.
CREATE TABLE oauth_providers (
    org_id           uuid        NOT NULL REFERENCES orgs (id),
    provider         text        NOT NULL CHECK (btrim(provider) <> '' AND length(provider) <= 64),
    name             text        NOT NULL CHECK (btrim(name) <> '' AND length(name) <= 100),
    scopes           text[]      NOT NULL DEFAULT '{}',
    connect_url      text        NOT NULL CHECK (connect_url LIKE 'https://%' OR connect_url LIKE 'http://%'),
    revoke_supported boolean     NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, provider)
);

-- One row per connected account of a person. No token, code or verifier column.
CREATE TABLE oauth_connections (
    id                uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id            uuid        NOT NULL REFERENCES orgs (id),
    user_id           uuid        NOT NULL REFERENCES users (id),
    provider          text        NOT NULL CHECK (btrim(provider) <> '' AND length(provider) <= 64),
    account_login     text        NOT NULL DEFAULT '' CHECK (length(account_login) <= 255),
    account_id        text        NOT NULL CHECK (btrim(account_id) <> '' AND length(account_id) <= 255),
    scopes            text[]      NOT NULL DEFAULT '{}',
    status            text        NOT NULL CHECK (status IN ('connected', 'refresh_failed', 'revoked')),
    generation        integer     NOT NULL DEFAULT 1 CHECK (generation >= 1),
    connected_at      timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz,
    last_refreshed_at timestamptz,
    last_error_code   text        CHECK (last_error_code IS NULL OR length(last_error_code) <= 64),
    UNIQUE (org_id, id),
    UNIQUE (org_id, user_id, provider, account_id)
);
CREATE INDEX oauth_connections_user_idx ON oauth_connections (org_id, user_id);

-- Sealed token set, one row per connection, replaced on each refresh (generation + 1).
CREATE TABLE oauth_token_material (
    org_id        uuid    NOT NULL REFERENCES orgs (id),
    connection_id uuid    PRIMARY KEY,
    generation    integer NOT NULL CHECK (generation >= 1),
    ciphertext    bytea   NOT NULL,
    wrapped_dek   bytea   NOT NULL,
    key_id        text    NOT NULL CHECK (btrim(key_id) <> ''),
    FOREIGN KEY (org_id, connection_id) REFERENCES oauth_connections (org_id, id) ON DELETE CASCADE
);

-- In-flight authorization: state stored as a hash, the PKCE verifier sealed.
CREATE TABLE oauth_flows (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id          uuid        NOT NULL REFERENCES orgs (id),
    user_id         uuid        NOT NULL REFERENCES users (id),
    provider        text        NOT NULL CHECK (btrim(provider) <> '' AND length(provider) <= 64),
    state_hash      bytea       NOT NULL UNIQUE CHECK (length(state_hash) = 32),
    sealed_verifier bytea       NOT NULL,
    return_to       text        NOT NULL CHECK (btrim(return_to) <> '' AND length(return_to) <= 2048),
    status          text        NOT NULL CHECK (status IN ('started', 'pending_confirm')),
    connection_id   uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES oauth_connections (org_id, id) ON DELETE CASCADE
);
CREATE INDEX oauth_flows_expiry_idx ON oauth_flows (expires_at);

-- An agent may use one person's connection (decision 10). Created only for the person's own
-- connections (checked in the API); the gateway reads it on every relay.
CREATE TABLE oauth_connection_grants (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id        uuid        NOT NULL REFERENCES orgs (id),
    agent_id      uuid        NOT NULL,
    connection_id uuid        NOT NULL,
    expires_at    timestamptz,
    created_by    uuid        NOT NULL REFERENCES users (id),
    created_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, connection_id) REFERENCES oauth_connections (org_id, id) ON DELETE CASCADE,
    UNIQUE (org_id, agent_id, connection_id)
);

ALTER TABLE oauth_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_providers
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE oauth_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_connections
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE oauth_token_material ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_token_material FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_token_material
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE oauth_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_flows
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE oauth_connection_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_connection_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_connection_grants
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

-- Gateway: owns the token path.
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_token_material TO locksmith_gateway;
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_flows TO locksmith_gateway;
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_connections TO locksmith_gateway;
GRANT SELECT, INSERT, UPDATE ON oauth_providers TO locksmith_gateway;
GRANT SELECT, DELETE ON oauth_connection_grants TO locksmith_gateway;
GRANT EXECUTE ON FUNCTION current_org_id() TO locksmith_gateway;
-- Read-only lookups: the person (without creating users) and the org.
GRANT SELECT ON users TO locksmith_gateway;

-- App (Rust control plane and NestJS): metadata only, never `oauth_token_material` or flows.
GRANT SELECT ON oauth_connections TO locksmith_app;
GRANT SELECT ON oauth_providers TO locksmith_app;
GRANT SELECT, INSERT, DELETE ON oauth_connection_grants TO locksmith_app;

RESET ROLE;
