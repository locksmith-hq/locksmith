-- S4 design decisions 2 and 4 (A0-4, A0-6): agent identities and their grants.
--
-- An agent row holds a name and the Argon2id PHC hash of its enrollment secret, never the
-- secret itself (it is shown once, at registration or rotation). A grant lets one agent relay
-- one secret (mode `relay` only in S4) until an optional expiry; the gateway reads unexpired
-- grants through the internal endpoint, never this table directly (S3 decision 2).
--
-- Both tables carry org_id under FORCE ROW LEVEL SECURITY. Grants point at their agent and
-- secret through composite foreign keys that include org_id, so a grant can never name another
-- org's agent or secret (foreign-key checks ignore RLS). Deleting an agent or a secret removes
-- its grants (ON DELETE CASCADE): access fails closed.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE agents (
    -- App-generated UUIDv7: the id is embedded in the enrollment secret before the insert.
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id          uuid        NOT NULL REFERENCES orgs (id),
    name            text        NOT NULL CHECK (btrim(name) <> ''),
    description     text        NOT NULL DEFAULT '',
    -- Argon2id PHC string (ls-crypto `hash_bearer_secret`).
    enrollment_hash text        NOT NULL CHECK (enrollment_hash LIKE '$argon2id$%'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- Target of the grants' composite FK; also the keyset-pagination index.
    UNIQUE (org_id, id),
    UNIQUE (org_id, name)
);

CREATE TABLE agent_grants (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id     uuid        NOT NULL,
    agent_id   uuid        NOT NULL,
    secret_id  uuid        NOT NULL,
    mode       text        NOT NULL DEFAULT 'relay' CHECK (mode IN ('relay')),
    -- NULL: no expiry. The gateway refuses a grant at or after this time.
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, secret_id) REFERENCES secrets (org_id, id) ON DELETE CASCADE,
    -- One grant per agent, secret and mode; leads with org_id like every unique key.
    UNIQUE (org_id, agent_id, secret_id, mode)
);
CREATE INDEX agent_grants_list_idx ON agent_grants (org_id, agent_id, id);
-- Cascade deletes from secrets look grants up by secret.
CREATE INDEX agent_grants_secret_idx ON agent_grants (org_id, secret_id);

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agents
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE agent_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_grants
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

-- Agents: register, rotate the enrollment hash (UPDATE), delete. Grants: create and revoke
-- (DELETE); a grant is never edited in place.
GRANT SELECT, INSERT, UPDATE, DELETE ON agents TO locksmith_app;
GRANT SELECT, INSERT, DELETE ON agent_grants TO locksmith_app;

RESET ROLE;
