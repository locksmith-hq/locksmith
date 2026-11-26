-- N1 task 2.1 (design: Data model, decisions 1, 3 and 8): notification rules, fan-out cursors,
-- inbox rows and delivery rows.
--
-- Rows hold identifiers and allow-listed display fields only (kind, actor id and name, object
-- name, time, link), never a secret value, a header, a body or a query string. The fan-out job
-- builds `notifications.payload` from typed ledger fields, never by copying an audit event.
--
-- Every table is per org with forced RLS. `notification_cursors` also lets the app role list all
-- rows with no org bound (the job_claim policies, as in migration 0010), because the fan-out job
-- must find the orgs it has to visit; it changes a cursor only while bound to that org's row.
--
-- Defaults: when an org is created a trigger seeds its rules matrix (inbox to the org owner) and
-- its cursor, in the creating transaction and under its org binding. Existing orgs are backfilled
-- at the end of this file. The audience resolves to the org owner until T6 roles exist.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE notification_rules (
    org_id           uuid    NOT NULL REFERENCES orgs (id),
    -- Closed NotifyKind set (N1 decision 2); T4 and T5 add values, so only the shape is checked.
    kind             text    NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
    channel          text    NOT NULL CHECK (channel IN ('inbox', 'email', 'slack')),
    audience         text    NOT NULL CHECK (audience IN ('owner', 'user')),
    audience_user_id uuid    REFERENCES users (id),
    enabled          boolean NOT NULL DEFAULT true,
    PRIMARY KEY (org_id, kind, channel),
    CHECK ((audience = 'user') = (audience_user_id IS NOT NULL))
);

ALTER TABLE notification_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notification_rules
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_rules TO locksmith_app;

CREATE TABLE notification_cursors (
    org_id   uuid   PRIMARY KEY REFERENCES orgs (id),
    -- Highest audit_events.seq the fan-out job has processed for this org.
    last_seq bigint NOT NULL DEFAULT 0 CHECK (last_seq >= 0)
);

ALTER TABLE notification_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notification_cursors
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());
-- The job lists every org's cursor with no org bound, then binds one org per transaction.
CREATE POLICY job_claim_select ON notification_cursors
    FOR SELECT TO locksmith_app
    USING (true);
GRANT SELECT, INSERT ON notification_cursors TO locksmith_app;
GRANT UPDATE (last_seq) ON notification_cursors TO locksmith_app;

CREATE TABLE notifications (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id     uuid        NOT NULL REFERENCES orgs (id),
    user_id    uuid        NOT NULL REFERENCES users (id),
    kind       text        NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
    -- Allow-listed fields only (N1 decision 6).
    payload    jsonb       NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    read_at    timestamptz
);
-- A user's inbox, newest first, and the unread count.
CREATE INDEX notifications_user_idx ON notifications (org_id, user_id, created_at DESC);
CREATE INDEX notifications_unread_idx ON notifications (org_id, user_id) WHERE read_at IS NULL;

ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notifications
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());
-- Items are written by the fan-out job and only marked read afterwards; never changed or deleted.
GRANT SELECT, INSERT ON notifications TO locksmith_app;
GRANT UPDATE (read_at) ON notifications TO locksmith_app;

CREATE TABLE notification_deliveries (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id          uuid        NOT NULL REFERENCES orgs (id),
    notification_id uuid        NOT NULL REFERENCES notifications (id),
    channel         text        NOT NULL CHECK (channel IN ('inbox', 'email', 'slack')),
    state           text        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'sent', 'failed')),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- A fixed error slug, never provider text (N1 decision 7).
    last_error_code text        CHECK (last_error_code ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (notification_id, channel)
);
CREATE INDEX notification_deliveries_pending_idx ON notification_deliveries (org_id, channel)
    WHERE state = 'pending';

ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notification_deliveries
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());
GRANT SELECT, INSERT ON notification_deliveries TO locksmith_app;
GRANT UPDATE (state, attempts, last_error_code) ON notification_deliveries TO locksmith_app;

-- Default rules matrix: every notifiable kind goes to the org owner's inbox; email and Slack
-- rows exist but start disabled, so an owner turns them on (task 4.2). Runs as the inserting
-- role, so the tenant_isolation WITH CHECK applies to the seeded rows too.
CREATE FUNCTION notification_defaults_for_org() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER
    SET search_path = public, pg_temp
    AS $$
BEGIN
    INSERT INTO notification_rules (org_id, kind, channel, audience, enabled)
        SELECT NEW.id, k.kind, c.channel, 'owner', c.channel = 'inbox'
        FROM (VALUES ('relay.denied'), ('git.denied'), ('grant.revoked'), ('agent.deleted')) AS k (kind)
        CROSS JOIN (VALUES ('inbox'), ('email'), ('slack')) AS c (channel)
        ON CONFLICT (org_id, kind, channel) DO NOTHING;
    INSERT INTO notification_cursors (org_id) VALUES (NEW.id) ON CONFLICT (org_id) DO NOTHING;
    RETURN NULL;
END
$$;

CREATE TRIGGER orgs_notification_defaults
    AFTER INSERT ON orgs
    FOR EACH ROW EXECUTE FUNCTION notification_defaults_for_org();

RESET ROLE;

-- Orgs that already exist (a local stack migrated before this file). The bootstrap login sees
-- every row; a later run as locksmith_owner sees none under FORCE RLS and adds nothing.
INSERT INTO notification_rules (org_id, kind, channel, audience, enabled)
    SELECT o.id, k.kind, c.channel, 'owner', c.channel = 'inbox'
    FROM orgs o
    CROSS JOIN (VALUES ('relay.denied'), ('git.denied'), ('grant.revoked'), ('agent.deleted')) AS k (kind)
    CROSS JOIN (VALUES ('inbox'), ('email'), ('slack')) AS c (channel)
    ON CONFLICT (org_id, kind, channel) DO NOTHING;
INSERT INTO notification_cursors (org_id)
    SELECT id FROM orgs
    ON CONFLICT (org_id) DO NOTHING;
