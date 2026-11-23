-- D3 design decision 10 and D3-1: the gateway's non-secret binding inventory.
--
-- The gateway publishes its bindings at startup (`PUT /internal/v1/gateway/bindings`); the latest
-- snapshot is kept per org (replaced whole, never merged) and served by `GET /v1/bindings`. The
-- items are `BindingSummary` objects: names, hosts, ports, users, databases, header names and
-- the like. The API types refuse unknown fields, so no password, header template, secret id or
-- key material can be stored, and no column here holds a value.
--
-- org_id sits under FORCE ROW LEVEL SECURITY and is the primary key: one row per org.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE gateway_bindings (
    org_id     uuid        PRIMARY KEY REFERENCES orgs (id),
    items      jsonb       NOT NULL CHECK (jsonb_typeof(items) = 'array'),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE gateway_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gateway_bindings
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

GRANT SELECT, INSERT, UPDATE ON gateway_bindings TO locksmith_app;

RESET ROLE;
