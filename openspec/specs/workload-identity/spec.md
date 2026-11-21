# workload-identity Specification

## Purpose

Let CI and machine workloads (GitHub Actions, Kubernetes) obtain short-lived agent tokens by presenting an external OIDC token that matches a pinned policy, with no stored Locksmith secret.

## Requirements

### Requirement: Org admins define workload identity trust policies
The control plane SHALL let an authenticated org member create, list, read and delete workload identities: a stored policy naming an issuer (`github` or `oidc` with an `https` URL), an existing agent of the same org, an audience and claim conditions. A policy SHALL be refused unless a condition pins the subject (`repository` for GitHub, `sub` otherwise) to a value other than a bare `*`. Policies carry no credential.

#### Scenario: Create a GitHub policy
- **WHEN** an admin creates a policy for issuer `github` with `repository = acme/api`, `ref = refs/heads/main` and agent `ci-deploy`
- **THEN** the policy is stored under the admin's org and `workload_identity.created` is appended to the audit ledger

#### Scenario: Unpinned policy refused
- **WHEN** a policy has only a `ref` condition, or `repository = *`
- **THEN** the response is `422` problem details and nothing is stored

#### Scenario: Another org's agent
- **WHEN** a policy names an agent id from a different org
- **THEN** the response is `404` and nothing is stored

### Requirement: An external identity token is exchanged for a short-lived agent token
`POST /v1/workload-tokens` SHALL accept an external OIDC JWT and a policy handle, verify the JWT (signature from the policy issuer's JWKS, `iss`, `aud`, `exp`, `nbf`, an algorithm allow-list without `none` or symmetric algorithms), require every claim condition of that policy to match, and return the ordinary 15-minute agent token of the policy's agent. The JWT SHALL NOT be stored, logged or traced, and every failure SHALL be the same `401` that does not say why.

#### Scenario: GitHub Actions job exchanges its token
- **WHEN** a job whose token carries `iss` GitHub, `repository` `acme/api` and `ref` `refs/heads/main` calls the endpoint
- **THEN** it receives an agent token whose `sub` is the policy's agent and that token passes gateway verification

#### Scenario: Claim mismatch
- **WHEN** the same repository's token carries `ref` `refs/heads/feature`
- **THEN** the response is `401`, no token is minted, and `workload_identity.denied` is appended with a reason slug and no token text

#### Scenario: Invalid external token
- **WHEN** the JWT is expired, signed by an unknown key after one JWKS refresh, uses `alg: none` or HS256, or has the wrong audience or issuer
- **THEN** the response is the same `401` as for a claim mismatch

#### Scenario: Kubernetes service account
- **WHEN** a pod presents a projected service account token for `system:serviceaccount:prod:deployer` with the policy's audience
- **THEN** it receives an agent token for the policy's agent; a token for another service account or namespace is refused

### Requirement: Issuer discovery is bounded and fail-closed
The control plane SHALL fetch an issuer's JWKS only over `https` from the exact issuer recorded in a stored policy (never from the presented token's `iss` or `jku` value), through the address guard (no loopback, private or link-local addresses unless the deployment explicitly allows it for local development), with response size and time limits and the existing JWKS cache refresh rate limit. An unreachable issuer SHALL fail closed.

#### Scenario: Token names an unlisted issuer
- **WHEN** a JWT's `iss` matches no stored policy
- **THEN** the response is `401` and no outbound request is made

#### Scenario: Issuer resolves to a private address
- **WHEN** a policy's issuer URL resolves to `169.254.169.254` or a private range in a non-dev deployment
- **THEN** no request is sent, the exchange fails with `401`, and creating the policy is refused with `422`

### Requirement: Exchange cannot widen access
A workload token SHALL carry only the agent id, org id, audience and times of an ordinary agent token, never claims copied from the external token. The workload's access SHALL be exactly the grants held by the policy's agent, checked by the gateway on every call. Deleting a policy or the agent, or revoking a grant, SHALL stop further exchanges or calls within the agent-token lifetime plus the grant cache TTL.

#### Scenario: Policy deleted
- **WHEN** an admin deletes the policy
- **THEN** the next exchange is refused, and a token minted earlier stops working no later than its expiry

#### Scenario: Grant revoked
- **WHEN** the agent's grant for a secret is revoked
- **THEN** a relay call from the workload is refused by the gateway even though its token is still valid

### Requirement: Replay and abuse are limited
The exchange SHALL reject an external token whose lifetime (`exp` minus `iat`) exceeds a configured maximum (default 1 hour), SHALL reject a repeated `jti` within the token's lifetime when the issuer supplies one, and SHALL be rate limited per policy and per source address.

#### Scenario: Replayed token
- **WHEN** the same GitHub token (same `jti`) is exchanged twice
- **THEN** the second exchange is refused

### Requirement: Workload identity events are audited without credentials
Creation and deletion of policies, successful exchanges and every denial SHALL be appended to the audit ledger with policy id, agent id, issuer, outcome, reason slug and the non-secret identifying claims named by the policy (for example repository and ref). No event, log line or trace SHALL contain an external token, an agent token or an enrollment secret.

#### Scenario: Leak scan after exchange flows
- **WHEN** the e2e exchange flows (success, claim mismatch, bad signature, replay) have run
- **THEN** `just leak-scan` finds no canary token in the database, logs or traces and `just audit-verify` passes

### Requirement: CLI, CI action and console
`smith login --workload github` SHALL read the runner-provided request URL and request token (`ACTIONS_ID_TOKEN_REQUEST_URL`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`), and `smith login --workload kubernetes` SHALL read a projected token file, request an external token for the policy audience, exchange it and keep only the resulting short-lived agent token in the existing 0600 `agent.json`. The console and desktop app SHALL list, create and delete workload identities and SHALL show no token.

#### Scenario: Login in CI writes only the agent token
- **WHEN** `smith login --workload github` runs in a job
- **THEN** it succeeds, `agent.json` holds only the agent token, endpoints and expiry, and no file or log holds the external token

#### Scenario: Console lists policies
- **WHEN** an admin opens the Workload identities page
- **THEN** it lists issuer, agent, conditions and last-used time, and a test asserts no token or secret field is rendered or requested
