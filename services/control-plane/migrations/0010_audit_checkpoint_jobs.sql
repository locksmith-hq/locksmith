-- S5 task 4.2 (design decision 4, A0-2): the checkpoint job's work table.
--
-- The checkpoint job runs as locksmith_app, which has no BYPASSRLS, so under FORCE ROW LEVEL
-- SECURITY it cannot list the orgs whose chains need a checkpoint: audit_heads and orgs show
-- only the bound org. This table is the job queue A0-2 asks for: one row per org that has a
-- chain, claimed with SELECT ... FOR UPDATE SKIP LOCKED so that several control-plane replicas
-- never checkpoint the same org at once. The claim locks this row, not the org's audit_heads
-- row, so appends never wait on a checkpoint signature.
--
-- A row holds the org id and when the job last looked at that org: nothing else. Reading every
-- row with no org bound is what the job needs, so the app role may SELECT all rows and lock them
-- (job_claim policies below); it may change a row only while bound to that row's org, and it can
-- never delete one. The heads, events and checkpoints stay isolated per org.
--
-- A row is created by a trigger when an org's audit_heads row is created (its first append), in
-- the appender's transaction and under its org binding.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE audit_checkpoint_jobs (
    org_id     uuid        PRIMARY KEY REFERENCES orgs (id),
    -- When the job last examined this org; each pass claims rows not yet examined in that pass.
    checked_at timestamptz NOT NULL DEFAULT '-infinity'
);
CREATE INDEX audit_checkpoint_jobs_checked_idx ON audit_checkpoint_jobs (checked_at);

ALTER TABLE audit_checkpoint_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoint_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_checkpoint_jobs
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());
-- The job finds and locks rows with no org bound (SELECT ... FOR UPDATE needs both policies).
CREATE POLICY job_claim_select ON audit_checkpoint_jobs
    FOR SELECT TO locksmith_app
    USING (true);
CREATE POLICY job_claim_lock ON audit_checkpoint_jobs
    FOR UPDATE TO locksmith_app
    USING (true)
    WITH CHECK (org_id = current_org_id());

GRANT SELECT, INSERT ON audit_checkpoint_jobs TO locksmith_app;
GRANT UPDATE (checked_at) ON audit_checkpoint_jobs TO locksmith_app;

-- Runs as the inserting role (locksmith_app during an append), so the tenant_isolation
-- WITH CHECK applies to the job row too.
CREATE FUNCTION audit_checkpoint_job_for_head() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER
    SET search_path = public, pg_temp
    AS $$
BEGIN
    INSERT INTO audit_checkpoint_jobs (org_id) VALUES (NEW.org_id) ON CONFLICT (org_id) DO NOTHING;
    RETURN NULL;
END
$$;

CREATE TRIGGER audit_heads_checkpoint_job
    AFTER INSERT ON audit_heads
    FOR EACH ROW EXECUTE FUNCTION audit_checkpoint_job_for_head();

RESET ROLE;

-- Orgs that already have a chain (a local stack migrated before this file). The bootstrap login
-- sees every row; a later run as locksmith_owner sees none under FORCE RLS and adds nothing.
INSERT INTO audit_checkpoint_jobs (org_id)
    SELECT org_id FROM audit_heads
    ON CONFLICT (org_id) DO NOTHING;
