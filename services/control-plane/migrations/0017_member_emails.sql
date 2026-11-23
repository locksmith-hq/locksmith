-- T6 task 4.3: the member list shows each member's email.
--
-- `users` is policed by the personal org and the login settings, so an org's other members were
-- invisible to it. This adds a read-only slice: a `users` row is visible while the bound org
-- (`app.org_id`) has a membership for that user. Unbound, `current_org_id()` is NULL and it
-- matches nothing. The subquery reads `memberships` under its own org policy. No write is
-- widened: INSERT and UPDATE still follow `tenant_isolation`.
SET LOCAL ROLE locksmith_owner;

CREATE POLICY org_member_read ON users FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM memberships m
            WHERE m.user_id = users.id
              AND m.org_id = current_org_id()
        )
    );

RESET ROLE;
