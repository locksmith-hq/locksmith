-- S1 design decision 4 (A0-4): two roles. locksmith_owner owns the schema and runs migrations;
-- locksmith_app serves requests and is neither table owner, superuser nor BYPASSRLS.
--
-- Idempotent. Roles are cluster-wide, so each is created only when missing (a concurrent CREATE
-- ROLE raises unique_violation, which is ignored). A deployment can pre-create both roles with
-- real passwords; this migration then creates nothing. The passwords below are local dev-only
-- values, listed with the compose credentials in infra/compose/.env.example.
--
-- The first run needs a login that may create roles and act as locksmith_owner (in dev, the
-- compose bootstrap superuser). Later runs can log in as locksmith_owner itself: it then owns
-- _sqlx_migrations and every table.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'locksmith_owner') THEN
        BEGIN
            CREATE ROLE locksmith_owner LOGIN PASSWORD 'locksmith-owner-dev-only'
                NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'locksmith_app') THEN
        BEGIN
            CREATE ROLE locksmith_app LOGIN PASSWORD 'locksmith-app-dev-only'
                NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
        END;
    END IF;

    -- Check each privilege separately: a list is true when any one of them is held.
    IF NOT (has_schema_privilege('locksmith_owner', 'public', 'USAGE')
            AND has_schema_privilege('locksmith_owner', 'public', 'CREATE')) THEN
        GRANT USAGE, CREATE ON SCHEMA public TO locksmith_owner;
    END IF;
    IF NOT has_schema_privilege('locksmith_app', 'public', 'USAGE') THEN
        GRANT USAGE ON SCHEMA public TO locksmith_app;
    END IF;

    -- Let later migrations run as locksmith_owner: hand it the bookkeeping table sqlx created
    -- under the bootstrap login.
    IF to_regclass('public._sqlx_migrations') IS NOT NULL
        AND (SELECT pg_get_userbyid(relowner) FROM pg_class
             WHERE oid = to_regclass('public._sqlx_migrations')) <> 'locksmith_owner' THEN
        ALTER TABLE public._sqlx_migrations OWNER TO locksmith_owner;
    END IF;
END
$$;
