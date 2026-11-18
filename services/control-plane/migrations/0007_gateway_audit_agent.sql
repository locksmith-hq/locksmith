-- S4 task 2.2: every relay audit row names the agent whose token made the call, including
-- refusals (no grant, expired grant). Nullable so rows written before this migration stay valid.
-- No foreign key: the audit outlives a deleted agent. An id cannot hold a secret.
SET LOCAL ROLE locksmith_owner;

ALTER TABLE gateway_audit ADD COLUMN agent_id uuid;

CREATE INDEX gateway_audit_org_agent_at_idx ON gateway_audit (org_id, agent_id, at DESC);

RESET ROLE;
