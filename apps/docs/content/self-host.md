# Self-host Locksmith

Run Locksmith on your own machine or cluster from the released images. Nothing here calls a Locksmith-operated service: licensing, billing or update-check failures never block start, unlock or export.

## Key custody: containment, not prevention

The bundled key provider is OpenBao in production mode with file storage. Its unseal key and root token live in the `openbao-keys` Docker volume. That is **containment**: it keeps secrets out of the agent's reach and out of the database, but anyone with root on the host can read that volume. For stronger custody, point Locksmith at an operator-run key provider (see "External keys").

## Compose

Prerequisites: Docker with the Compose plugin, `openssl` (or `/dev/urandom`), and ports 8080 and 8090 free on localhost.

```sh
git clone https://github.com/locksmith-hq/locksmith && cd locksmith
just selfhost-up            # bootstrap secrets, then docker compose up --wait
```

Without `just`: `bash infra/compose/selfhost/bootstrap.sh`, then `docker compose --env-file infra/compose/selfhost/.env -f infra/compose/selfhost/compose.yaml up -d --wait`.

### What is generated

`bootstrap.sh` writes `infra/compose/selfhost/.env` (mode 0600, never committed) with fresh Postgres, app, owner, audit-verifier and gateway-service passwords, the agent signing key, and the OpenBao tokens. It keeps existing values on re-run, prints setting names only (never values), and refuses known dev-only values.

### Options

- `--external-keys`: skip the bundled OpenBao; set `OPENBAO_ADDR` and the three `OPENBAO_*_TOKEN` values in `.env` yourself.
- `--tls`: add the Caddy reverse proxy (set `LOCKSMITH_DOMAIN`; set `LOCKSMITH_TLS_BIND_ADDR=0.0.0.0` to publish).
- `--demo-oidc`: add the demo Keycloak issuer. **Not for production.**
- Own sign-in: set `LOCKSMITH_OIDC_ISSUER`, `LOCKSMITH_OIDC_AUDIENCE` and `LOCKSMITH_OIDC_JWKS_URL` in `.env` to any OIDC issuer and leave the demo profile off.

### Backup

Back up two things together, offline and encrypted:

1. `infra/compose/selfhost/.env` (the generated secrets);
2. the `openbao-data` and `openbao-keys` volumes, plus `pgdata` (or a `pg_dump`).

Losing `openbao-keys` makes stored keys unrecoverable. Never store the backup next to the agents' workspace.

### Upgrade

Set `LOCKSMITH_VERSION` (or the `*_IMAGE` variables) in `.env`, then `docker compose --env-file infra/compose/selfhost/.env -f infra/compose/selfhost/compose.yaml pull` and `just selfhost-up` again. Migrations run on start; data, keys and secrets are kept. `just selfhost-down` stops the stack and keeps volumes; `just selfhost-down -v` deletes them.

## Helm

Prerequisites: a Kubernetes cluster, `helm`, and three existing Secrets: the database connection (`DATABASE_URL`, `DATABASE_OWNER_URL`), the internal tokens (`LOCKSMITH_GATEWAY_SERVICE_TOKEN`, `LOCKSMITH_AGENT_SIGNING_KEY`) and the key-provider credentials (the `OPENBAO_*_TOKEN` values). The chart reads only their **names**; `values.schema.json` rejects a literal password or token. OIDC issuer, audience and JWKS URL are public values set under `oidc`, and `keyProvider.address` is your OpenBao address.

```sh
helm install locksmith infra/helm/locksmith \
  --set secrets.database.existingSecret=locksmith-db \
  --set secrets.internal.existingSecret=locksmith-internal \
  --set secrets.keyProvider.existingSecret=locksmith-keys \
  --set keyProvider.address=https://openbao.example.internal:8200
```

A hook Job applies migrations; pods run non-root with a read-only root filesystem and dropped capabilities, and a NetworkPolicy limits traffic. Upgrade with `helm upgrade` and a new image digest. Back up the Postgres database and your key provider as above.
