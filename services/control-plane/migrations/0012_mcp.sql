-- M1 remote MCP (task 1.4): the per-org tool switches and the clients that signed in.
--
-- `mcp_tool_settings` holds only OVERRIDES of a tool's default. The default on/off table lives
-- in `ls-mcp-server` (the registry), so an absent row means "use the default" and a new tool
-- needs no migration. The server refuses to list or call a tool that is off (hub design
-- section 6); these rows are what it reads.
--
-- `mcp_clients` is one row per `(org, layer, client_id, principal)` (design "Client binding for
-- revoke"): on the hub `client_id` is the OAuth client id carried in the access token and
-- `principal` the signed-in person; on the agent layer `client_id` is the agent id and
-- `principal` the agent id as well, because an agent token has no client id. Revoking sets
-- `revoked_at`; a token is refused when its `auth_time` is before it. The row is never deleted
-- by the app, so a revoked client cannot make itself new again by registering again.
--
-- Neither table holds a token, a secret or a secret value: ids, names and times only.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE mcp_tool_settings (
    org_id     uuid        NOT NULL REFERENCES orgs (id),
    layer      text        NOT NULL CHECK (layer IN ('hub', 'agent')),
    tool       text        NOT NULL CHECK (btrim(tool) <> '' AND length(tool) <= 100),
    enabled    boolean     NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, layer, tool)
);

CREATE TABLE mcp_clients (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id        uuid        NOT NULL REFERENCES orgs (id),
    layer         text        NOT NULL CHECK (layer IN ('hub', 'agent')),
    client_id     text        NOT NULL CHECK (btrim(client_id) <> '' AND length(client_id) <= 255),
    principal     text        NOT NULL CHECK (btrim(principal) <> '' AND length(principal) <= 255),
    -- The client's display name from registration (informational, never a key).
    client_name   text        NOT NULL DEFAULT '' CHECK (length(client_name) <= 200),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    -- NULL: active. Set once by the revoke endpoint and never cleared by the app.
    revoked_at    timestamptz,
    UNIQUE (org_id, layer, client_id, principal)
);

ALTER TABLE mcp_tool_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_tool_settings
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE mcp_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_clients FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_clients
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

-- Switches are upserted and flipped, never deleted (an absent row is the default).
GRANT SELECT, INSERT ON mcp_tool_settings TO locksmith_app;
GRANT UPDATE (enabled, updated_at) ON mcp_tool_settings TO locksmith_app;
-- Clients are recorded on initialize (insert, then refresh the name and last-seen time) and
-- revoked; never deleted, and identity columns never change.
GRANT SELECT, INSERT ON mcp_clients TO locksmith_app;
GRANT UPDATE (client_name, last_seen_at, revoked_at) ON mcp_clients TO locksmith_app;

RESET ROLE;
