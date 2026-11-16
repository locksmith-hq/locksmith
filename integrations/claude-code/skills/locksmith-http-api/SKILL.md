---
name: locksmith-http-api
description: Use when calling an authenticated HTTP API (Stripe, OpenAI, GitHub API, any REST endpoint) that needs an API key or bearer token. Issue an opaque lsk_ token instead of using the real key.
---

# HTTP APIs with opaque tokens

You never get the real key. You get an `lsk_` placeholder; the Locksmith HTTP relay swaps in the real credential for approved hosts only.

1. `locksmith_list_keys` to find the key name.
2. `locksmith_issue_token` with `key` (optional `provider`, `hosts`, `placement`), or `smith token issue <KEY> [--host api.example.com] [--provider <name>] [--placement bearer|basic|header:<Name>|query:<param>]`. Needs a session with the `http` scope.
3. Use the returned token as the credential in your request or app config, and use the returned base URL (when given) so traffic goes through the relay. Pass the token only as the credential; it is a placeholder, not the key.

Notes:
- The token works only for its approved hosts and only for the issuing session. A request to another host is refused (`http_host_not_bound`): the human must add the host under `[http.keys]` in `.locksmith.toml` and start a new session. Do not add it yourself.
- `smith token ls` lists live tokens; `smith http providers` lists the built-in provider catalog (hosts and placement presets).
- Do not extract or "unwrap" the token, and do not try to read the real key from the vault or environment.
