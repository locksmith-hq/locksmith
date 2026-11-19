-- S5 design decisions 5 and 6, task 3.1: relay audit goes to the ledger only.
--
-- gateway_audit becomes read-only legacy: the gateway now appends relay.attempt,
-- relay.outcome and relay.denied events through the control plane
-- (POST /internal/v1/audit/events), so the app role loses INSERT. SELECT stays, so the rows
-- written before S5 remain readable. Rollback is a code revert plus a new migration that grants
-- INSERT again (design.md, Migration Plan); this file is never edited once applied.
--
-- relay.outcome is idempotent on its attempt (design decision 5): the gateway retries an outcome
-- up to 3 times, keyed by the attempt event's id. The append endpoint checks for an existing
-- outcome under the org's head lock; this partial unique index is the backstop, so one attempt
-- can never have two outcome events. It reads only the identifier-typed attempt_id attribute.
SET LOCAL ROLE locksmith_owner;

REVOKE INSERT ON gateway_audit FROM locksmith_app;

CREATE UNIQUE INDEX audit_events_outcome_attempt_uidx
    ON audit_events (org_id, (attrs -> 'attempt_id' ->> 'id'))
    WHERE kind = 'relay.outcome';

RESET ROLE;
