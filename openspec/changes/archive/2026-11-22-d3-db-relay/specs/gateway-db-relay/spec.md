## ADDED Requirements

### Requirement: Gateway relays Postgres sessions with an injected password
The gateway SHALL accept Postgres frontend/backend protocol 3.0 connections on a dedicated listener, select the binding named by the client's `database` startup parameter, authenticate to the bound upstream server with the stored password, and then relay the session in both directions. The client SHALL never receive the password or any value derived from it.

#### Scenario: psql runs a query through the gateway
- **WHEN** an agent with a relay grant connects `psql` to the gateway naming a bound database and runs `SELECT current_user`
- **THEN** the query returns the bound upstream role, and the agent's environment, files and process arguments contain no database password

#### Scenario: Upstream SCRAM-SHA-256
- **WHEN** the upstream server requires SCRAM-SHA-256
- **THEN** the gateway completes SCRAM with the stored password and the client sees an ordinary `AuthenticationOk`

#### Scenario: Cancel request reaches the upstream
- **WHEN** a client sends a `CancelRequest` for a running `SELECT pg_sleep(30)` using the backend key it received from the gateway
- **THEN** the upstream query is cancelled, and the backend key the client saw is not the upstream server's key

### Requirement: Agent authenticates to the listener over TLS
The listener SHALL require TLS before the startup message and SHALL authenticate the client by a cleartext password message carrying a valid agent token over that TLS channel. Connections without TLS, with an invalid or expired token, or with a token for another gateway audience SHALL be refused with a Postgres `ErrorResponse` (SQLSTATE `28000` or `28P01`) before any upstream connection or decrypt.

#### Scenario: Plaintext startup refused
- **WHEN** a client sends a `StartupMessage` without first completing TLS
- **THEN** the gateway answers with an `ErrorResponse` and closes the connection, making no upstream call

#### Scenario: Invalid agent token
- **WHEN** a client completes TLS and sends an expired agent token as its password
- **THEN** the gateway answers SQLSTATE `28P01`, makes no upstream call and no decrypt call, and logs the refusal by slug only, with no ledger event since no agent identity exists

### Requirement: Binding and grant limit the target
A Postgres password SHALL be decrypted and used only for a binding that exists in the gateway configuration, only for an agent holding an unexpired relay grant for that binding's secret, and only to the binding's fixed host, port, user and database. A client-supplied `user`, `options` or other startup parameter SHALL NOT change the upstream user, host or database. The upstream address SHALL pass the gateway's address guard (private and loopback addresses only when the binding allows them).

#### Scenario: Unbound database name
- **WHEN** the client names a database that is not a configured binding
- **THEN** the gateway answers SQLSTATE `3D000`, makes no upstream call and no decrypt call

#### Scenario: No grant for the binding
- **WHEN** a valid agent without a grant for the binding's secret connects
- **THEN** the gateway answers SQLSTATE `28000` and records a denied ledger event without decrypting

#### Scenario: Client tries to switch upstream user
- **WHEN** the client sends `user=postgres` and `options=-c role=postgres` in its startup message
- **THEN** the upstream session still runs as the bound user with no client-supplied options applied

### Requirement: Upstream authentication is safe
The gateway SHALL connect upstream over TLS according to the binding's mode (`require` by default, `verify-full` supported, `disable` allowed only for private or loopback hosts the binding allows) and SHALL refuse to send a cleartext password upstream unless the upstream leg is TLS or loopback.

#### Scenario: Cleartext over plain network refused
- **WHEN** a non-loopback upstream without TLS requests cleartext password authentication
- **THEN** the gateway sends no password, answers the client with a fixed error and records the failure

### Requirement: No password in output, logs or the ledger
Server `ErrorResponse` and `NoticeResponse` text relayed to the client SHALL be redacted of the password in every form the relay redactor covers. Gateway logs, traces and ledger events SHALL never contain the password or the agent token. Ledger events SHALL record binding, upstream host, upstream user, outcome, duration and byte counts, and SHALL NOT record query text or result rows.

#### Scenario: Upstream echoes the password in an error
- **WHEN** the upstream sends an `ErrorResponse` whose message contains the password
- **THEN** the client sees a redaction marker instead, and `just leak-scan` finds no canary in logs, traces or the database

#### Scenario: Session is audited
- **WHEN** an agent opens and closes a relayed session
- **THEN** the ledger holds a `db.session.opened` and a `db.session.closed` event for it, `just audit-verify` passes, and neither event carries query text

### Requirement: Revocation and expiry close open sessions
An open relayed session SHALL be closed by the gateway within the grant cache TTL after its grant is revoked or expires, or its agent token expires.

#### Scenario: Grant revoked mid-session
- **WHEN** the grant behind an open session is revoked
- **THEN** the gateway closes both legs within the grant cache TTL and records `db.session.closed` with reason `revoked`

### Requirement: Client setup keeps the password off the agent host
`smith db connect <name> --gateway <url>` SHALL run the given client (or print connection settings) pointed at the gateway with TLS required and the agent token as the only credential, and SHALL write no database password or agent token to disk.

#### Scenario: Connect writes nothing to disk
- **WHEN** an agent runs `smith db connect app --gateway <url> -- psql -c 'select 1'`
- **THEN** the command succeeds, the child sees `PGSSLMODE` of at least `require`, and `db connect` creates or modifies no file holding the agent token or a database password (the existing 0600 `agent.json` from `smith login --agent` excepted; home is snapshotted before and after), and no file anywhere holds a database password
