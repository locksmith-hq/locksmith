-- t5-honey-tokens task 4.1: the default notification rule for `honey.triggered`. A decoy used by an
-- agent is a high-signal event, so by default the org owner gets it in the inbox and by email
-- (Slack stays off until an owner enables it). Replaces the defaults function from 0019 so new
-- orgs get the rows, and backfills the orgs that already exist. Existing rows are never changed.
SET LOCAL ROLE locksmith_owner;

CREATE OR REPLACE FUNCTION notification_defaults_for_org() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER
    SET search_path = public, pg_temp
    AS $$
BEGIN
    INSERT INTO notification_rules (org_id, kind, channel, audience, enabled)
        SELECT NEW.id, k.kind, c.channel, 'owner', c.channel = 'inbox'
        FROM (VALUES ('relay.denied'), ('git.denied'), ('grant.revoked'), ('agent.deleted')) AS k (kind)
        CROSS JOIN (VALUES ('inbox'), ('email'), ('slack')) AS c (channel)
        ON CONFLICT (org_id, kind, channel) DO NOTHING;
    INSERT INTO notification_rules (org_id, kind, channel, audience, enabled)
        SELECT NEW.id, 'honey.triggered', c.channel, 'owner', c.channel IN ('inbox', 'email')
        FROM (VALUES ('inbox'), ('email'), ('slack')) AS c (channel)
        ON CONFLICT (org_id, kind, channel) DO NOTHING;
    INSERT INTO notification_cursors (org_id) VALUES (NEW.id) ON CONFLICT (org_id) DO NOTHING;
    RETURN NULL;
END
$$;

RESET ROLE;

-- Existing orgs. The bootstrap login sees every row; a later run as locksmith_owner sees none
-- under FORCE RLS and adds nothing.
INSERT INTO notification_rules (org_id, kind, channel, audience, enabled)
    SELECT o.id, 'honey.triggered', c.channel, 'owner', c.channel IN ('inbox', 'email')
    FROM orgs o
    CROSS JOIN (VALUES ('inbox'), ('email'), ('slack')) AS c (channel)
    ON CONFLICT (org_id, kind, channel) DO NOTHING;
