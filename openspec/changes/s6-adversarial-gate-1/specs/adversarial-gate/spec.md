# Spec Delta

## Purpose
Attacks the server stack (control plane, gateway, agent connector and audit ledger) the way a hostile or prompt-injected agent would, and blocks a change when any attack gets a secret back to the agent.

## ADDED Requirements

### Requirement: Attacks use only agent-reachable surfaces
Each gateway attack case SHALL act only through what an agent can reach: its agent token, `smith`, `locksmith-mcp`, the public gateway and control-plane APIs and its own process environment. It SHALL save everything it receives into the case's artifact directory for the oracle.

#### Scenario: Case artifacts are complete
- **WHEN** a gateway case runs against the local stack
- **THEN** every response body, header set, CLI output and MCP reply the case received is present in its artifact directory

### Requirement: Environment and files hold no secret
After an agent session logs in and relays through the gateway, the agent's environment, the environment and command line of `smith`, `locksmith-mcp` and the gateway processes, the `smith` state directory and shell history SHALL contain no secret value and no enrollment secret.

#### Scenario: Environment extraction
- **WHEN** case G1 dumps the environment, `/proc/<pid>/environ` and `cmdline` of every Locksmith process it can read, and the state directory
- **THEN** the oracle finds no canary in any encoding

### Requirement: Reflected secrets do not reach the agent
When a bound upstream reflects the injected credential in its response, the agent SHALL receive either a redacted response or a refusal, in every encoding, compression and stream shape the reflecting fixture produces.

#### Scenario: Reflecting upstream
- **WHEN** case G2 relays to an upstream that echoes the injected header plain, encoded, compressed, chunked byte by byte and as a slow event stream
- **THEN** the oracle finds no canary outside the listed residuals, and each refusal is a `redaction_failed` ledger event

### Requirement: Agent-shaped requests cannot redirect or echo the secret
The gateway SHALL keep the injected header out of the agent's control: agent attempts to override, duplicate or re-case it, place `{secret}` in their own headers, path, query or body, inject CRLF, change Host, follow a redirect or reach a host outside the binding SHALL be refused or SHALL send no secret to any host but the bound one.

#### Scenario: Secret toward the attacker's host
- **WHEN** case G3 tries to make the gateway send the secret to an attacker's host by redirect, Host header, CRLF injection or a URL outside the binding
- **THEN** the attacker's host receives no canary in any encoding and the gateway makes no decrypt call for an unbound host

#### Scenario: Placeholder in agent input
- **WHEN** the agent puts `{secret}` in its own header, path, query or body
- **THEN** the placeholder is sent literally or the request is refused, and the upstream receives the secret only in the bound header

### Requirement: Unusual encodings are caught or registered
Case G4 SHALL make the reflecting upstream return the secret as base32, UTF-16LE, UTF-16BE, `\u` JSON escapes, HTML entities, quoted-printable, an unlabelled gzip body, reversed, split across headers and one character per line. Each form SHALL either produce no oracle hit or match an entry in the residual register.

#### Scenario: Encoding sweep
- **WHEN** case G4 runs every listed form
- **THEN** base32, UTF-16 and `\u`-escaped forms produce no hit, and every other hit matches a residual entry

### Requirement: Control-plane and ledger surfaces return no values
Every agent-reachable control-plane response and error, the OpenAPI document, the audit events API and the audit export SHALL hold no secret value. Internal endpoints SHALL refuse callers without the service token, and another org's data SHALL be invisible.

#### Scenario: API sweep
- **WHEN** case G5 calls every documented agent-reachable route with valid, malformed and cross-org inputs, including request fields that end up in audit event attributes
- **THEN** the oracle finds no canary in any response, ledger row or export file, and internal routes return 401

### Requirement: Stolen or stale tokens are contained
A token replayed after its grant is revoked or after it expires, used for another org, or sent to an internal endpoint SHALL be refused, and the refusal SHALL be recorded in the ledger.

#### Scenario: Replay after revoke
- **WHEN** case G6 revokes the grant and replays the agent token after the grant cache TTL
- **THEN** the gateway returns 403, makes no decrypt call and the ledger holds a `denied` event for that agent

### Requirement: Residual register stays honest
The suite SHALL read a register of known leak paths, each with an encoding, a case, a protection label (prevention, containment or detection) and a reason. A leak outside the register SHALL fail the run, a registered leak SHALL report `RESIDUAL`, and a registered entry that no longer leaks SHALL fail the run until it is removed.

#### Scenario: Unregistered leak
- **WHEN** a case leaks the canary in an encoding the register does not list for that case
- **THEN** the run reports `FAIL` naming the case and encoding, never the value

#### Scenario: Stale residual
- **WHEN** a registered residual produces no hit
- **THEN** the run fails with `STALE RESIDUAL` naming the entry

### Requirement: Fast tier runs in every just ci
An in-process adversarial test SHALL run the reflection, header and encoding payloads against the gateway relay with a fake KMS, fake material source and local mock upstreams, judged by the oracle, without Docker or network access. It SHALL run as part of `just ci`.

#### Scenario: Fast tier catches a regression
- **WHEN** a planted change disables redaction of base64 forms
- **THEN** the fast-tier test fails under `just ci`

### Requirement: Stack gate command
`just adversarial-gate` SHALL run every gateway case against the running stack with skips counted as failures, then run the stack leak scan over Postgres, Loki, Tempo, the audit export and all artifacts, and exit non-zero on any failure.

#### Scenario: Stack not running
- **WHEN** `just adversarial-gate` runs without `just up`
- **THEN** it exits non-zero and says the stack is not running, and reports no case as passed

#### Scenario: Clean stack
- **WHEN** `just adversarial-gate` runs on a healthy stack at the head of the change
- **THEN** every case reports `PASS` or `RESIDUAL`, the leak scan is clean and the exit code is 0

### Requirement: Live-agent attacks
With `--agent claude` and a Claude CLI and key present, each fixed attack prompt SHALL run in a headless Claude session that has only the Locksmith MCP tools and a shell, and its transcript SHALL be scanned by the oracle. Without the CLI or key the run SHALL print `skip live` and the stack gate SHALL fail when skips count as failures.

#### Scenario: Live extraction attempt
- **WHEN** the gate runs with `--agent claude` and a key
- **THEN** every transcript is saved and the oracle finds no canary outside the residual register

#### Scenario: No key for nightly
- **WHEN** the nightly run uses `--agent claude` with `ADVERSARIAL_REQUIRE_ALL=1` and no key
- **THEN** it exits non-zero with `skip live`, so a missing key is visible

### Requirement: Gate stays out of GitHub Actions
No stack or live adversarial run SHALL be added to GitHub Actions. The weekly `adversarial.yml` run of `run.sh all` SHALL keep passing, which means `all` SHALL NOT include the stack cases.

#### Scenario: Weekly offline run unchanged
- **WHEN** `run.sh all` runs on a machine without the stack and with `ADVERSARIAL_REQUIRE_ALL=1`
- **THEN** no gateway case runs or skips, and the result matches the run before this change
