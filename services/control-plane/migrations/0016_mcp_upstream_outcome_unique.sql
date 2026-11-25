-- m2-mcp-gateway task 4.1: mcp.upstream_outcome is idempotent on its attempt, as relay.outcome is
-- (migration 0009). The append endpoint checks for an existing outcome under the org's head
-- lock; this partial unique index is the backstop, so one forwarded call can never have two
-- outcome events. It reads only the identifier-typed attempt_id attribute.
SET LOCAL ROLE locksmith_owner;

CREATE UNIQUE INDEX audit_events_mcp_upstream_outcome_attempt_uidx
    ON audit_events (org_id, (attrs -> 'attempt_id' ->> 'id'))
    WHERE kind = 'mcp.upstream_outcome';

RESET ROLE;
