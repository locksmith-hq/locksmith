# Design: M10e

## D1. Injectable keys are an allow-list in the policy
`agent-policy.toml` gains `[projects.<p>] inject = ["KEY", ...]` (default empty). `AgentSessionStart`
snapshots the list onto the lease (`Lease.inject`, `Some` only for agent leases; `None` means no
restriction), and the daemon enforces it in the run path. Human-started leases are unchanged. A
refused key returns `Denied` with `relay_only: X is relay-only for agent sessions ...`, naming the
policy file, and is audited `BLOCKED relay_only` once per key with the key name, never a value. The
check runs on the final key set (binding keys, `--only`, `--all`) before any value is read or token
minted, so no flag combination skips it and a mixed request injects nothing. Keys the binding routes
through `[http.keys]` are not injected at all (the child gets an opaque token), so they are not
refused. Other injection paths: `smith gh` puts the stored credential in `GH_TOKEN` when it is a
personal access token, so for agent leases that key must be in `inject` too; GitHub App mode (a
one-hour installation token) and `smith aws --contained` (15-minute STS credentials limited by the
project's session policy) inject derived, short-lived credentials, never the stored key, and keep
their own rules. `--aws` (delegated) injects dummy keys only.

## D2. Relay hosts come from the policy for agent sessions
`[projects.<p>.http.<KEY>] hosts = ["us.cloud.langfuse.com"]`. For agent leases a token carries the
policy hosts (or the hosts asked for, when the policy lists every one); the binding is used only for
placement/provider details, and neither binding nor catalog hosts count. A key with no policy hosts
is not relayed at all. Refusals are audited `BLOCKED relay_host:<host>` (`relay_host:none` for a key
with no hosts). The relay's per-request authorization re-checks the request host against the policy
for agent leases, so a token minted from an edited binding (`smith run` mints from the client's
copy) still cannot reach another host. The pinned binding (M6 gate A3) still governs everything else
and human leases. Matching is exact host (`:443` implied) or a one-level wildcard (`*.github.com`
matches `api.github.com`, not `a.b.github.com` or `github.com`), never a suffix match.

## D3. Network guard
Before dialing upstream, resolve the name once and check every address; skip blocked ones, fail if
none remain, then connect to a checked address (no second resolution; the resolver is injectable for
tests). Blocked by default: loopback, RFC-1918, link-local, ULA, IPv6 link-local, CGN, unspecified /
`0.0.0.0/8`, broadcast, IPv4-mapped forms of all of these, and the cloud metadata addresses
`169.254.169.254` and `fd00:ec2::254` (blocked even if allowlisted). `[relay] allow_private =
["127.0.0.1:3000"]` in the policy opens exact `ip:port` targets (names are refused at load); it is
applied at unlock to all sessions. The guard sits in the shared upstream dial (`ls-proxy`
`forward::connect_to`), so it covers the HTTP relay, the AWS relay and the Git forwarder; their
public upstreams keep working, but a private Git or API host now needs an `allow_private` entry (and
so an agent policy file), also for human-only use. Not covered: connections through `HTTPS_PROXY`
(the proxy resolves the name), database relays (private targets are their normal case), GitHub App
and STS token requests (fixed public hosts), and the debug-only plain-HTTP test switch.

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
