-- S3 design decision 8: the gateway's append-only relay audit. One row per relay call. It never
-- holds the secret value, request or response headers, bodies or the query string: only who
-- (secret id), where (scheme, host, method, path) and what happened (outcome, status).
--
-- The control plane's migrator owns the schema, so the table lives here; the gateway connects
-- as locksmith_app. That role may INSERT and SELECT, never UPDATE or DELETE.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE gateway_audit (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id     uuid        NOT NULL REFERENCES orgs (id),
    secret_id  uuid        NOT NULL,
    at         timestamptz NOT NULL DEFAULT now(),
    method     text        NOT NULL CHECK (btrim(method) <> ''),
    scheme     text        NOT NULL CHECK (scheme IN ('http', 'https')),
    host       text        NOT NULL CHECK (btrim(host) <> ''),
    path       text        NOT NULL,
    -- 'ok', 'denied_host', 'denied_address', 'upstream_error', 'redaction_failed', ...
    outcome    text        NOT NULL CHECK (btrim(outcome) <> ''),
    -- Upstream HTTP status; NULL when no upstream call was made.
    status     integer     CHECK (status IS NULL OR status BETWEEN 100 AND 599),
    -- Request correlation id, for joining with traces.
    request_id text
);

CREATE INDEX gateway_audit_org_at_idx ON gateway_audit (org_id, at DESC);

ALTER TABLE gateway_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gateway_audit
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

-- Append-only: no UPDATE, no DELETE.
GRANT SELECT, INSERT ON gateway_audit TO locksmith_app;

RESET ROLE;
