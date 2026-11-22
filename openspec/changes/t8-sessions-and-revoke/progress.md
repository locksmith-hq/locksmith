## 2026-11-22 worker
- Task: planning review fixes - done
- Verified: openspec validate t8-sessions-and-revoke -> valid; just quick -> clean
- Notes for next session: spec/design/tasks now agree on 15 s liveness and `token_jti` key.

## 2026-11-22 worker
- Task: planning review fixes - done
- Verified: openspec validate t8-sessions-and-revoke -> valid; just quick -> clean
- Notes for next session: added jti task 1.0; no admin role exists, so authorization narrowed to org member like existing revoke routes. All 6 threads resolved; review reruns on push.

## 2026-11-22 worker
- Task: 1.0 jti claim on AgentClaims - done
- Verified: cargo nextest run -p ls-control-plane agent_token workload_exchange -> 10 passed; ls-gateway builds; just quick (below)
- Notes for next session: branched from main (not t3, merge conflicted in control-plane-client index.ts); 1.1 touches that client, so rebase-free merge main first.
