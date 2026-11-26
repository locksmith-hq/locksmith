-- Honey tokens (openspec change t5-honey-tokens): decoy secrets that look real but are never valid.
-- A honey secret is a normal secret row with kind 'honey'; only its template and state are stored
-- here, the value is sealed in secret_versions like any other.
ALTER TABLE secrets
    ADD COLUMN kind text NOT NULL DEFAULT 'standard' CHECK (kind IN ('standard', 'honey')),
    ADD COLUMN honey_template text,
    ADD COLUMN disabled_at timestamptz,
    ADD CONSTRAINT secrets_honey_template_chk CHECK (
        (kind = 'honey' AND honey_template IN ('aws_access_key', 'github_pat', 'slack_token', 'generic_api_key'))
        OR (kind = 'standard' AND honey_template IS NULL AND disabled_at IS NULL)
    );
CREATE INDEX secrets_honey_idx ON secrets (org_id, environment_id) WHERE kind = 'honey';
