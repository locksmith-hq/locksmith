-- T10 audit streaming (Enterprise) task 1.2: where an org's audit events are streamed and how far
-- each destination has got.
--
-- `audit_stream_destinations` holds one OTLP endpoint per row. `header_refs` maps an HTTP header
-- name to a secret id (a reference, never a value): the exporter resolves it at send time, so no
-- header value, token or key is ever stored here. `last_error` is a static, short reason.
-- `audit_stream_cursor` is the last ledger `seq` a destination acknowledged, so a restart resumes
-- with no gap and no reorder.
--
-- Both tables carry org_id under FORCE ROW LEVEL SECURITY. The cursor points at its destination
-- through a composite foreign key that includes org_id (foreign-key checks ignore RLS), so a
-- cursor can never name another org's destination; deleting a destination deletes its cursor.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE audit_stream_destinations (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id          uuid        NOT NULL REFERENCES orgs (id),
    endpoint        text        NOT NULL CHECK (btrim(endpoint) <> '' AND length(endpoint) <= 2048),
    protocol        text        NOT NULL DEFAULT 'otlp_http' CHECK (protocol IN ('otlp_http', 'otlp_grpc')),
    -- {"<header name>": "<secret uuid>"}; values are secret ids, never header values.
    header_refs     jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(header_refs) = 'object'),
    enabled         boolean     NOT NULL DEFAULT true,
    last_error      text        CHECK (last_error IS NULL OR length(last_error) <= 256),
    last_success_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- Target of the cursor's composite FK; also the keyset-pagination index.
    UNIQUE (org_id, id)
);

CREATE TABLE audit_stream_cursor (
    org_id         uuid   NOT NULL,
    destination_id uuid   NOT NULL,
    -- The last `audit_events.seq` the destination acknowledged.
    last_seq       bigint NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
    PRIMARY KEY (org_id, destination_id),
    FOREIGN KEY (org_id, destination_id) REFERENCES audit_stream_destinations (org_id, id) ON DELETE CASCADE
);

ALTER TABLE audit_stream_destinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_stream_destinations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_stream_destinations
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE audit_stream_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_stream_cursor FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_stream_cursor
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON audit_stream_destinations TO locksmith_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_stream_cursor TO locksmith_app;

RESET ROLE;
