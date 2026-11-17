-- S2 design decision 6 (A0-4, A0-7): envelope-encrypted secret versions. A row holds only the
-- A0-7 ciphertext blob, the KMS-wrapped data key (`dek-wrap` blob) and the KMS key id; the
-- control plane cannot unwrap the DEK (its OpenBao token may only encrypt), so a dump of this
-- table yields no plaintext. The AEAD binds org_id, secret_id and version, so a blob moved to
-- another row fails to open.
--
-- Versions are append-only for the app role: it may INSERT and SELECT, never UPDATE or DELETE.
-- Deleting the parent secret removes its versions through the foreign key's ON DELETE CASCADE
-- (a referential action, not an app-role DELETE).
SET LOCAL ROLE locksmith_owner;

-- Target of the composite foreign key below, so a version can never name another org's secret
-- (foreign-key checks ignore RLS).
ALTER TABLE secrets ADD CONSTRAINT secrets_org_id_id_key UNIQUE (org_id, id);

CREATE TABLE secret_versions (
    org_id      uuid        NOT NULL,
    secret_id   uuid        NOT NULL,
    -- 1, 2, 3, ... per secret; also part of the AEAD binding.
    version     integer     NOT NULL CHECK (version >= 1),
    -- A0-7: header(20) || nonce(12) || ciphertext || tag(16).
    ciphertext  bytea       NOT NULL CHECK (octet_length(ciphertext) >= 48),
    -- A0-7 `dek-wrap`: header(20) || nonce(12) || wrapped DEK(32) || tag(16).
    wrapped_dek bytea       NOT NULL CHECK (octet_length(wrapped_dek) = 80),
    -- The KMS key the DEK is wrapped under, e.g. `gateway:v1`.
    key_id      text        NOT NULL CHECK (btrim(key_id) <> ''),
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- Leads with org_id like every unique key (S1 decision 6); version is unique per secret.
    PRIMARY KEY (org_id, secret_id, version),
    FOREIGN KEY (org_id, secret_id) REFERENCES secrets (org_id, id) ON DELETE CASCADE
);

ALTER TABLE secret_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secret_versions
    USING (org_id = current_org_id())
    WITH CHECK (org_id = current_org_id());

-- Append-only: no UPDATE, no DELETE.
GRANT SELECT, INSERT ON secret_versions TO locksmith_app;

RESET ROLE;
