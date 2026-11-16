---
name: locksmith-db
description: Use when connecting to a Postgres, MySQL or Redis database (psql, migrations, ORM, queries) that needs a password, or when asked for a DATABASE_URL.
---

# Databases without the password

`smith db connect <name>` opens a local password-less relay for `[db.<name>]` in `.locksmith.toml`; Locksmith authenticates upstream. Needs a session with the `db` scope.

- Print the endpoint: `smith db connect <name>` (prints a local URL on 127.0.0.1).
- Run a command against it: `smith db connect <name> -- psql` (the command gets PG*/MYSQL_*/REDIS_URL and DATABASE_URL pointing at the relay).
- Use only the local endpoint. Never ask for, search for or hard-code the real password or upstream URL, and never read it from `.env`.
- Unknown `<name>` or a refusal: tell the human; see `locksmith-blocked`.
