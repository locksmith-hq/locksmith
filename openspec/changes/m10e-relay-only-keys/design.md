# Design: M10e

## D1. Injectable keys are an allow-list in the policy
`agent-policy.toml` gains `[projects.<p>] inject = ["KEY", ...]` (default empty). The daemon enforces
it in the run path for leases created by `AgentSessionStart` (`Lease.agent == true`). Human-started
leases are unchanged. A refused key returns `Denied: key X is relay-only for agent sessions; use an
http token` and is audited `BLOCKED relay_only` with the key name, never a value. The check runs on
the final key set (binding keys, `--only`, `--all`), so no flag combination skips it.

## D2. Relay hosts come from the policy for agent sessions
`[projects.<p>.http.<KEY>] hosts = ["us.cloud.langfuse.com"]`. For agent leases the daemon computes
`effective_hosts = policy_hosts` and uses the binding only for placement/provider details; a binding
host not in the policy is dropped, a key with no policy hosts is not relayed at all. The pinned
binding (M6 gate A3) still governs everything else. Matching is exact host or a one-level wildcard
(`*.github.com`), never a suffix match.

## D3. Network guard
Before dialing upstream, resolve the name and check every address; skip blocked ones, fail if none
remain, then connect to the checked address (no second resolution). Blocked by default: loopback,
RFC-1918, link-local, ULA, CGN, unspecified, and the cloud metadata addresses (the metadata ones are
blocked even if allowlisted). `[relay] allow_private = ["127.0.0.1:3000"]` in the policy opens exact
internal targets. The existing relay hosts for AWS/Git keep working because their upstreams are public.

## D4. Response redaction is a tested guarantee
The relay already decodes and redacts response bodies and headers (ls-proxy `http.rs`). Add tests with
an echo upstream returning the injected header and body, for gzip/br and for a value split across
chunks, and state the limit: only the exact value and its standard encodings (as `ls-redact` covers)
are caught, so a policy host that reflects the key in a transformed form is out of scope; host
choice is the human's.

## D5. Honest limits
Relays do not stop an agent from *using* a key against an approved host; they stop it from *having*
or *redirecting* it. `smith run` for injectable keys remains a trusted-command feature and the docs say
so. The policy file stays human-owned (checked path, outside git work trees, read at unlock).

## D6. Compatibility
No `inject` list means agent sessions can no longer `run` any key until the human adds one. That is a
deliberate tightening; the m10b `locksmith-sessions` skill and the policy example are updated, and the
refusal message names the policy file.
