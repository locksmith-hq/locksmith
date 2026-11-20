-- T1 design decision 6 (A0-4, A0-5): human users, keyed by (issuer, subject).
--
-- One row per verified identity. `personal_org_id` is the org the identity acts in: a first
-- sign-in creates that org (one transaction, see src/users.rs); a later identity that carries
-- the same VERIFIED email joins the existing personal org instead (identity linking). Email is
-- informational and never a key: `sub` is (OIDC Core 5.7). Only the verified-email index below
-- is used to link, and only for rows whose email the issuer reported as verified.
--
-- Rows hold public identity claims only: never a token, code, password or client secret.
--
-- RLS: the usual tenant policy (the personal org is the tenant), plus three transaction-local
-- login settings the sign-in transaction binds before any org is known: `app.login_issuer`,
-- `app.login_subject` (a row is visible to exactly its own identity) and `app.login_email` (a
-- VERIFIED row is visible to a caller claiming the same verified email, for linking). Unset,
-- they are NULL and match nothing, so every other transaction sees only its own org's rows.
-- Inserts must match the bound identity and the bound org, so a request cannot create a user for
-- an identity or org it was not authenticated as.
SET LOCAL ROLE locksmith_owner;

CREATE TABLE users (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    issuer          text        NOT NULL CHECK (btrim(issuer) <> ''),
    subject         text        NOT NULL CHECK (btrim(subject) <> ''),
    email           text        CHECK (email IS NULL OR btrim(email) <> ''),
    email_verified  boolean     NOT NULL DEFAULT false,
    personal_org_id uuid        NOT NULL REFERENCES orgs (id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);
-- Linking by verified email; also the org-side lookup.
CREATE INDEX users_verified_email_idx ON users (lower(email)) WHERE email_verified;
CREATE INDEX users_personal_org_idx ON users (personal_org_id);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users
    USING (
        personal_org_id = current_org_id()
        OR (issuer = NULLIF(current_setting('app.login_issuer', true), '')
            AND subject = NULLIF(current_setting('app.login_subject', true), ''))
        OR (email_verified
            AND lower(email) = NULLIF(current_setting('app.login_email', true), ''))
    )
    WITH CHECK (
        personal_org_id = current_org_id()
        AND issuer = NULLIF(current_setting('app.login_issuer', true), '')
        AND subject = NULLIF(current_setting('app.login_subject', true), '')
    );

-- Users are created at first sign-in and their email claims refreshed; never deleted or
-- re-pointed at another org by the app.
GRANT SELECT, INSERT ON users TO locksmith_app;
GRANT UPDATE (email, email_verified) ON users TO locksmith_app;

RESET ROLE;
