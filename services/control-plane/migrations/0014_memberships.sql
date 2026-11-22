-- T6 design decisions 1, 3 and 7: org membership and invites.
--
-- `memberships(org_id, user_id, role)` says who may act in which org; `users.personal_org_id`
-- stays the default org. `invites` holds only the SHA-256 of a single-use token, never the token.
--
-- Both tables are under FORCE ROW LEVEL SECURITY. Beyond the usual `org_id = current_org_id()`
-- policy, two transaction-local settings open exactly one more slice each (unset they are NULL
-- and match nothing, like the T1 login settings):
--   * `app.login_user` (a user id): a membership row is visible to its own user across orgs, so
--     the request path can find the orgs a caller belongs to before any org is bound.
--   * `app.invite_hash` (hex SHA-256): exactly the invite with that hash is visible to the
--     accepting user, may be marked accepted while still valid, and may be answered by exactly
--     one membership insert for the invited role.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE memberships (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id     uuid        NOT NULL REFERENCES orgs (id),
    user_id    uuid        NOT NULL REFERENCES users (id),
    role       text        NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);

CREATE TABLE invites (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id      uuid        NOT NULL REFERENCES orgs (id),
    email       text        NOT NULL CHECK (email = lower(email) AND btrim(email) <> ''),
    role        text        NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    token_hash  bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    invited_by  uuid        NOT NULL REFERENCES users (id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at  timestamptz,
    UNIQUE (org_id, id)
);
CREATE INDEX invites_org_idx ON invites (org_id);

-- Backfill: every existing user owns their personal org. Run before RLS is enabled on the new
-- tables. `users` is FORCE'd and the migration role has no tenant bound, so lift FORCE for this
-- one statement and restore it (same transaction, so it is never observable).
ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
INSERT INTO memberships (org_id, user_id, role)
    SELECT personal_org_id, id, 'owner' FROM users
    ON CONFLICT (org_id, user_id) DO NOTHING;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE invites FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON memberships
    USING (
        org_id = current_org_id()
        OR user_id = NULLIF(current_setting('app.login_user', true), '')::uuid
    )
    WITH CHECK (org_id = current_org_id());
-- Accepting an invite: the accepting user inserts their own row, for exactly the invited org
-- and role, while the invite is still open and bound by `app.invite_hash`.
CREATE POLICY join_by_invite ON memberships FOR INSERT
    WITH CHECK (
        user_id = NULLIF(current_setting('app.login_user', true), '')::uuid
        AND EXISTS (
            SELECT 1 FROM invites i
            WHERE i.org_id = memberships.org_id
              AND i.role = memberships.role
              AND i.token_hash = decode(NULLIF(current_setting('app.invite_hash', true), ''), 'hex')
              AND i.accepted_at IS NULL
              AND i.revoked_at IS NULL
              AND i.expires_at > now()
        )
    );

CREATE POLICY tenant_isolation ON invites
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());
CREATE POLICY read_by_hash ON invites FOR SELECT
    USING (token_hash = decode(NULLIF(current_setting('app.invite_hash', true), ''), 'hex'));
CREATE POLICY accept_by_hash ON invites FOR UPDATE
    USING (
        token_hash = decode(NULLIF(current_setting('app.invite_hash', true), ''), 'hex')
        AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()
    )
    WITH CHECK (token_hash = decode(NULLIF(current_setting('app.invite_hash', true), ''), 'hex'));

-- Members change role, join and leave; invites are created, listed, revoked or accepted, never
-- re-pointed or deleted by the app.
GRANT SELECT, INSERT, DELETE ON memberships TO locksmith_app;
GRANT UPDATE (role) ON memberships TO locksmith_app;
GRANT SELECT, INSERT ON invites TO locksmith_app;
GRANT UPDATE (accepted_at, revoked_at) ON invites TO locksmith_app;

RESET ROLE;
