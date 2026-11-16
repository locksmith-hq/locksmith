---
name: locksmith
description: Use whenever a task needs a credential, API key, token, password, .env value, authenticated API call, Git push to a private host, AWS or database access. Locksmith lets you do these without ever seeing the secret.
---

# Locksmith: you never hold the secret

Locksmith brokers credentials. You ask it to perform authenticated work; it injects or attaches the secret outside your view and redacts output.

Rules:
- Never read `.env` files, shell history, keychains or config files to find a credential. Hooks block this; do not look for a way around them.
- Never print, echo, log, commit or paste a secret value. You should not have one.
- Run commands that need secrets as `smith run -- <command>`; add `--only KEY1,KEY2` to limit which keys are injected. `smith env-template` prints key names only.
- In a session you started yourself (`locksmith_start_session`), `smith run` injects only the keys the human's agent policy lists under `inject` (`locksmith_status` shows them). Every other key is relay-only: use an `lsk_` token. A `relay_only` refusal is final; do not try `--yes`, `smith gh` or another route.
- For HTTP APIs use an opaque `lsk_` token (skill `locksmith-http-api`). Git, AWS and databases have their own paths (`locksmith-git`, `locksmith-aws`, `locksmith-db`).
- MCP tools (server `locksmith`): `locksmith_list_keys` (key names only), `locksmith_status`, `locksmith_start_session`, `locksmith_issue_token`, `locksmith_explain_block`.
- Everything needs an active session (`locksmith-sessions`). If an action is blocked, follow `locksmith-blocked`.
- A key that is not listed does not exist for this project. Tell the human; never ask for the value in chat.

Not available yet: `request_secret`, `rotate_secret`, automatic blocking and a human approval prompt. Do not reference them as working features.
