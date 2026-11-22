-- D4 design decisions 2, 3 and 4: workload identity trust policies.
--
-- A policy links one issuer (GitHub Actions, or an https OIDC issuer such as a Kubernetes
-- cluster) and a list of claim conditions to one existing agent. A workload that proves it
-- matches is handed an ordinary agent token for that agent, so grants apply unchanged. The
-- table holds no secret: the issuer, audience and conditions are configuration.
--
-- org_id sits under FORCE ROW LEVEL SECURITY. The agent is named through a composite foreign
-- key that includes org_id, so a policy can never point at another org's agent; deleting the
-- agent deletes its policies (access fails closed).
SET LOCAL ROLE locksmith_owner;

CREATE TABLE workload_identities (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id       uuid        NOT NULL REFERENCES orgs (id),
    name         text        NOT NULL CHECK (btrim(name) <> ''),
    issuer_kind  text        NOT NULL CHECK (issuer_kind IN ('github', 'oidc')),
    issuer       text        NOT NULL CHECK (issuer LIKE 'https://%'),
    audience     text        NOT NULL CHECK (btrim(audience) <> ''),
    agent_id     uuid        NOT NULL,
    -- [{claim, op: eq|prefix, value}], validated in Rust before insert.
    conditions   jsonb       NOT NULL CHECK (jsonb_typeof(conditions) = 'array'
                                             AND jsonb_array_length(conditions) > 0),
    created_by   uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id) ON DELETE CASCADE,
    UNIQUE (org_id, id),
    UNIQUE (org_id, name)
);
-- Cascade deletes from agents look policies up by agent.
CREATE INDEX workload_identities_agent_idx ON workload_identities (org_id, agent_id);

ALTER TABLE workload_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE workload_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workload_identities
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

-- A policy is created, read, deleted, and touched for last_used_at; never edited otherwise.
GRANT SELECT, INSERT, DELETE ON workload_identities TO locksmith_app;
GRANT UPDATE (last_used_at) ON workload_identities TO locksmith_app;

RESET ROLE;
