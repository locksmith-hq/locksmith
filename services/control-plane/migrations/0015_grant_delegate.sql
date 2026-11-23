-- D2: a `delegate` grant lets the gateway vend short-lived, scoped cloud credentials to the
-- agent. It carries an allow-list (`scope`); relay grants carry none.
ALTER TABLE agent_grants DROP CONSTRAINT agent_grants_mode_check;
ALTER TABLE agent_grants
    ADD CONSTRAINT agent_grants_mode_check CHECK (mode IN ('relay', 'delegate')),
    ADD COLUMN scope jsonb,
    ADD CONSTRAINT agent_grants_scope_check CHECK (
        (mode = 'delegate' AND scope IS NOT NULL AND jsonb_typeof(scope) = 'object')
        OR (mode = 'relay' AND scope IS NULL)
    );
