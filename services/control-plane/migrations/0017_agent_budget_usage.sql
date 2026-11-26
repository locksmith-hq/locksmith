-- T9 task 3.1: the per-agent daily call counter behind the gateway's budget leases. One row per
-- (org, agent, grant or the agent as a whole, UTC day). `grant_id` NULL is the agent-wide budget.
-- `used` counts calls leased to gateways (never more than the daily limit the caller sent);
-- `last_granted` is the size of the most recent lease, so one atomic upsert can both count and
-- report what it granted. Counts and ids only: no secret, token or call content.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE agent_budget_usage (
    org_id       uuid        NOT NULL REFERENCES orgs (id),
    agent_id     uuid        NOT NULL,
    grant_id     uuid,
    day          date        NOT NULL,
    used         integer     NOT NULL CHECK (used >= 0),
    last_granted integer     NOT NULL DEFAULT 0 CHECK (last_granted >= 0),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id) ON DELETE CASCADE
);

-- NULL grant ids are one agent-wide row: the unique key folds NULL to the nil uuid.
CREATE UNIQUE INDEX agent_budget_usage_key_uidx
    ON agent_budget_usage (org_id, agent_id, (COALESCE(grant_id, '00000000-0000-0000-0000-000000000000'::uuid)), day);

ALTER TABLE agent_budget_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_budget_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_budget_usage
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

-- Leases insert a day's row and raise `used`; rows are never deleted by the app.
GRANT SELECT, INSERT ON agent_budget_usage TO locksmith_app;
GRANT UPDATE (used, last_granted, updated_at) ON agent_budget_usage TO locksmith_app;

RESET ROLE;
