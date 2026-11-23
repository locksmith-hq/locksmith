-- T6 task 3.2 (design decision 7): `GET /v1/orgs` lists every org the caller belongs to.
--
-- `orgs` is policed by `id = current_org_id()`, so with no org bound a caller could not read the
-- names of its own team orgs. This adds a read-only slice: an org row is visible when the
-- transaction-local `app.login_user` (set only after the bearer token is verified) has a
-- membership in it. Unset, the setting is NULL and matches nothing. The subquery reads
-- `memberships` under its own policy, whose `app.login_user` slice shows exactly that user's
-- rows. No write is widened: INSERT and UPDATE still need the org bound.
SET LOCAL ROLE locksmith_owner;

CREATE POLICY member_read ON orgs FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM memberships m
            WHERE m.org_id = orgs.id
              AND m.user_id = NULLIF(current_setting('app.login_user', true), '')::uuid
        )
    );

RESET ROLE;
