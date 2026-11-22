-- T8 live sessions, revoke and pause (t8-sessions-and-revoke task 1.1).
--
-- `agent_sessions` is the gateway's report of agent sessions (open, heartbeat, close). One row per
-- session; `token_jti` is the `jti` claim of the agent token the session was opened with, the key
-- between a session and the token the gateway sees. A session is live while `last_seen_at` is
-- within three heartbeats (15 s) and it is not revoked; `revoked_at` is set once by the revoke
-- endpoints and never cleared by the app.
--
-- `orgs.agents_paused` is the org-wide pause flag: while true the gateway refuses every agent
-- request. Both default to "not revoked, not paused", so the gateway and control plane can deploy
-- in either order.
--
-- Neither carries a token, a secret value or an upstream address: ids, a kind, a binding slug and
-- times only. `token_jti` is an identifier, not a credential, and no API response returns it.
SET LOCAL ROLE locksmith_owner;

ALTER TABLE orgs ADD COLUMN agents_paused boolean NOT NULL DEFAULT false;

CREATE TABLE agent_sessions (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id       uuid        NOT NULL REFERENCES orgs (id),
    agent_id     uuid        NOT NULL,
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id) ON DELETE CASCADE,
    token_jti    uuid        NOT NULL,
    kind         text        NOT NULL CHECK (kind IN ('http', 'pg', 'mcp')),
    -- The binding slug the session targets (never a hostname or address).
    slug         text        NOT NULL DEFAULT '' CHECK (length(slug) <= 100),
    started_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    -- NULL: not revoked. Set once by revoke-one or revoke-all.
    revoked_at   timestamptz
);

CREATE INDEX agent_sessions_org_live ON agent_sessions (org_id, last_seen_at DESC);
CREATE INDEX agent_sessions_jti ON agent_sessions (org_id, token_jti);

ALTER TABLE agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_sessions
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

-- Sessions are reported (insert, heartbeat) and revoked; never deleted by the app, and identity
-- columns never change. `orgs` already grants UPDATE to the app role.
GRANT SELECT, INSERT ON agent_sessions TO locksmith_app;
GRANT UPDATE (last_seen_at, revoked_at) ON agent_sessions TO locksmith_app;

RESET ROLE;
