-- S5 design decisions 1, 2, 4 and 8 (A0-4, A0-5, A0-6, A0-11): the per-org audit ledger.
--
-- audit_events is one linear SHA-256 chain per org: seq starts at 1 with no gaps, prev_hash is
-- the previous event's hash (32 zero bytes for seq 1) and hash covers every column through the
-- canonical encoding in crates/ls-audit. Rows hold identifiers only (kind, actor, target,
-- outcome and attrs are allow-listed identifier types in ls-audit), never a secret value, a
-- header value, a body or a query string.
--
-- audit_heads holds each org's latest seq and hash. An append locks that row (SELECT ... FOR
-- UPDATE), hashes in Rust, inserts the event and moves the head, all in one transaction with
-- app.org_id set, so appends for one org are serialised and the chain stays linear.
--
-- The app role may INSERT and SELECT events and checkpoints, never UPDATE or DELETE them; on
-- audit_heads it may only create the row and move seq and hash. The database owner can still
-- rewrite rows: this detects tampering (verify, signed checkpoints, the export), it does not
-- prevent it (design decision 9).
--
-- There are no foreign keys from checkpoints to events, so the owner-role tamper tests can delete
-- events behind a checkpoint and verify must report it.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE audit_heads (
    org_id     uuid        PRIMARY KEY REFERENCES orgs (id),
    seq        bigint      NOT NULL DEFAULT 0 CHECK (seq >= 0),
    hash       bytea       NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
                           CHECK (length(hash) = 32),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    org_id    uuid        NOT NULL REFERENCES orgs (id),
    seq       bigint      NOT NULL CHECK (seq >= 1),
    -- UUIDv7 chosen by the appender: it is part of the hashed encoding.
    id        uuid        NOT NULL UNIQUE,
    at        timestamptz NOT NULL,
    -- Static codes from ls-audit (`relay.attempt`, `agent.created`, ...); new kinds need no
    -- migration, so only the shape is checked here.
    kind      text        NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
    -- `agent:<uuid>`, `user:<uuid>` or `service:<code>`.
    actor     text        NOT NULL CHECK (actor ~ '^[a-z]+:[a-z0-9_.-]{1,64}$'),
    -- `secret:<uuid>`, `agent:<uuid>`, `grant:<uuid>`, ...; NULL when the event has no target.
    target    text        CHECK (target ~ '^[a-z]+:[a-z0-9_.-]{1,64}$'),
    outcome   text        NOT NULL CHECK (outcome ~ '^[a-z][a-z0-9_.]{0,63}$'),
    -- Identifier-typed attributes only, e.g. {"host": {"host": "api.example.com"}}.
    attrs     jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(attrs) = 'object'),
    prev_hash bytea       NOT NULL CHECK (length(prev_hash) = 32),
    hash      bytea       NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (org_id, seq)
);
-- Newest-first listing (S5 task 6.1).
CREATE INDEX audit_events_org_at_idx ON audit_events (org_id, at DESC);

-- Signed checkpoints (design decision 4): Ed25519 over the ls-audit checkpoint bytes.
CREATE TABLE audit_checkpoints (
    id        uuid        NOT NULL UNIQUE DEFAULT uuidv7(),
    org_id    uuid        NOT NULL REFERENCES orgs (id),
    seq       bigint      NOT NULL CHECK (seq >= 1),
    hash      bytea       NOT NULL CHECK (length(hash) = 32),
    at        timestamptz NOT NULL,
    -- The signing key's name and version, e.g. `audit-checkpoint:1`.
    key_id    text        NOT NULL CHECK (btrim(key_id) <> ''),
    signature bytea       NOT NULL CHECK (length(signature) = 64),
    PRIMARY KEY (org_id, seq)
);

-- One row per `locksmith-audit verify` run per org (design decision 8).
CREATE TABLE audit_verify_runs (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    org_id        uuid        NOT NULL REFERENCES orgs (id),
    mode          text        NOT NULL CHECK (mode IN ('db', 'dir')),
    started_at    timestamptz NOT NULL,
    finished_at   timestamptz NOT NULL DEFAULT now(),
    ok            boolean     NOT NULL,
    events        bigint      NOT NULL CHECK (events >= 0),
    checkpoints   bigint      NOT NULL CHECK (checkpoints >= 0),
    -- The first broken seq and why ('sequence', 'link', 'hash', 'checkpoint'), when not ok.
    broken_seq    bigint,
    break_kind    text        CHECK (break_kind IN ('sequence', 'link', 'hash', 'checkpoint')),
    -- Set when the chain ends before the latest checkpoint.
    truncated_at  bigint
);
CREATE INDEX audit_verify_runs_org_idx ON audit_verify_runs (org_id, finished_at DESC);

ALTER TABLE audit_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_heads
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_events
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE audit_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_checkpoints
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

ALTER TABLE audit_verify_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_verify_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_verify_runs
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

-- App role. Events and checkpoints: append and read only. Heads: create the row and move seq,
-- hash and updated_at (the only UPDATE in the ledger; also what SELECT ... FOR UPDATE needs).
-- Verify runs: read only (the API reports the latest one).
GRANT SELECT, INSERT ON audit_events TO locksmith_app;
GRANT SELECT, INSERT ON audit_checkpoints TO locksmith_app;
GRANT SELECT, INSERT ON audit_heads TO locksmith_app;
GRANT UPDATE (seq, hash, updated_at) ON audit_heads TO locksmith_app;
GRANT SELECT ON audit_verify_runs TO locksmith_app;

RESET ROLE;

-- The verifier role (design decision 8): SELECT on the ledger with BYPASSRLS, so it walks every
-- org, plus INSERT on audit_verify_runs only. Used only by the `locksmith-audit` CLI, never by a
-- service. Created only when missing, like the roles in 0001 (creating a BYPASSRLS role needs
-- the bootstrap superuser; a deployment pre-creates it with a real password). The password is a
-- local dev-only value, listed in infra/compose/.env.example.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_verifier') THEN
        BEGIN
            CREATE ROLE audit_verifier LOGIN PASSWORD 'locksmith-audit-verifier-dev-only'
                NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;
    IF NOT has_schema_privilege('audit_verifier', 'public', 'USAGE') THEN
        GRANT USAGE ON SCHEMA public TO audit_verifier;
    END IF;
END
$$;

SET LOCAL ROLE locksmith_owner;

GRANT SELECT ON audit_heads, audit_events, audit_checkpoints, audit_verify_runs TO audit_verifier;
GRANT INSERT ON audit_verify_runs TO audit_verifier;

-- The CLI binds app.org_id to the org it has just verified before recording the run, and this
-- policy only admits rows for that org. BYPASSRLS exempts the role from RLS today, so the policy
-- is the rule the CLI follows and becomes binding if a deployment drops BYPASSRLS.
CREATE POLICY verifier_records_verified_org ON audit_verify_runs
    FOR INSERT TO audit_verifier
    WITH CHECK (org_id = current_org_id());

RESET ROLE;
