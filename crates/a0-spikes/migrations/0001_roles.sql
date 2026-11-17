-- A0 decision 4: migrations run as an owner role; the app logs in as a role that is neither
-- table owner, superuser nor BYPASSRLS. Roles are cluster-wide, so this is idempotent and safe
-- when several spike databases migrate at once (a concurrent CREATE ROLE raises unique_violation).
-- The password is a local dev-only value, like the compose credentials in infra/compose/.env.example.
DO $$
BEGIN
    BEGIN
        CREATE ROLE a0_owner NOLOGIN;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
    END;
    BEGIN
        CREATE ROLE a0_app LOGIN PASSWORD 'a0-app-dev-only'
            NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
    END;
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO a0_owner;
GRANT USAGE ON SCHEMA public TO a0_app;
