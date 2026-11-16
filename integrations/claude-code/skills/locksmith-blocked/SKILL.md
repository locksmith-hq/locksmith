---
name: locksmith-blocked
description: Use immediately when a Locksmith action, hook or MCP call is blocked, denied, revoked, expired or locked, or when a needed key or secret is missing.
---

# When blocked

1. Stop. Do not retry, rephrase, or try another route to the same secret (reading `.env`, env vars, other shells, other keys, editing `.locksmith.toml` or the agent policy).
2. Call `locksmith_explain_block` with the exact block message or rule id (e.g. `agent_policy`, `relay_only`, `relay_host`, `http_host_not_bound`, `expired`, `revoked`, `locked`, `attestation`, `role`).
3. Tell the human in plain words: what you were doing, the rule that blocked it, and what they would need to do (unlock, start a session, approve a host, change the policy). Then wait.

Missing key: if `locksmith_list_keys` does not show it, say "KEY_NAME is not available to this project/environment; please add it to the vault (or bind it in .locksmith.toml)". Never ask the human to paste the value into chat.

Revoked means the human ended the session on purpose: do nothing further with Locksmith until told.

Not available yet: `request_secret`, `rotate_secret`, automatic blocking and an in-session human approval prompt. Today the human acts out of band.
