## Why
Git over HTTPS is the commonest authenticated operation an agent performs, and it cannot use the JSON relay: clones and pushes are large, streamed, binary smart-HTTP exchanges. Today the Git path exists only in the local daemon forwarder (M5, `crates/ls-proxy/src/github.rs`, `smith git setup`). The hosted gateway buffers whole bodies (`services/gateway/src/relay.rs`, `Bytes`), so a hosted-org agent has no way to `git clone`/`git push` without holding a token.

## What changes (usable outcome)
An enrolled agent runs `smith git setup` once, then plain `git clone`, `git fetch` and `git push` against a bound GitHub repository work with **no token in its environment, config, history or process list**. The gateway streams the smart-HTTP exchange to GitHub, injecting the stored credential (PAT or GitHub App installation token) only for the bound host and repository paths, and writes a ledger event per operation.

## Out of scope
- SSH transport, non-GitHub hosts (GitLab, Bitbucket) and the `gh` API proxy (the existing M5 path stays as is).
- Per-branch or per-ref push policy (T2 policy engine) and signed-commit enforcement.
- Cloud (AWS) deployment of the route.
- Redacting packfile contents: pack data is the agent's own repository; only headers and the text error channel are scanned.

## Depends on
none (builds on the shipped S3 relay, S4 connector and S5 ledger).
