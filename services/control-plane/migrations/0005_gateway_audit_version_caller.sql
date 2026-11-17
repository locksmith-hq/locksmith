-- S3 task 3.3: the relay audit names the secret version and the caller (spec "Every relay call
-- is audited"). Nullable so rows written before this migration stay valid. Neither column can
-- hold a value: the version is a number, the caller an identity name (S3: one static caller).
SET LOCAL ROLE locksmith_owner;

ALTER TABLE gateway_audit
    ADD COLUMN version integer CHECK (version IS NULL OR version >= 1),
    ADD COLUMN caller  text    CHECK (caller IS NULL OR btrim(caller) <> '');

RESET ROLE;
