## Why
CI jobs and cluster workloads are agents too, but today the only way to give one an identity is an enrollment secret (`lse_...`, S4): a long-lived bearer secret that someone has to store in a GitHub Actions secret or a Kubernetes Secret. That is exactly the standing credential Locksmith exists to remove. GitHub Actions and Kubernetes already issue every job and pod a short-lived, signed OIDC identity token; the control plane can verify it and trade it for the same 15-minute agent token an enrolled agent gets, so nothing static is stored on the runner or in the cluster.

Today `POST /v1/agent-tokens` (`services/control-plane/src/api/agents.rs`) accepts only an enrollment secret. The JWKS machinery for external issuers exists (`auth/jwks.rs`, `auth/human.rs` from T1) but is wired to one human issuer only.

## What changes (usable outcome)
An org admin signed in to the console (or using the API) creates a **workload identity**: a trust policy that says "tokens from issuer X whose claims match Y may act as agent Z". A GitHub Actions job with `permissions: id-token: write`, or a pod with a projected service account token, runs `smith login --workload github` (or `kubernetes`) and gets a 15-minute agent token, then uses `smith relay`, `smith git`, `smith db connect` and the rest exactly like any agent. **No Locksmith secret, enrollment secret or cloud key is stored in the repository, workflow secrets or the cluster.**

- New capability `workload-identity`: trust policies, a token-exchange endpoint, claim matching, and audit.
- New control-plane routes: workload identity CRUD (human auth) and `POST /v1/workload-tokens` (presents an external OIDC JWT, no other credential).
- Exchanged tokens are ordinary agent tokens for an existing agent, so grants (S4), the gateway and every delegation (D1 to D3) work unchanged and revoking the agent's grants cuts the workload off.
- `smith login --workload <github|kubernetes>`; a composite GitHub Action in `integrations/github-action`; web console and desktop pages to manage workload identities; `just workload-smoke` with a local OIDC issuer.

Protection is labelled honestly: the absence of a stored Locksmith credential on the runner is **prevention**; what a matching workflow can do with its grants is only **contained** (15-minute token, grants and policy claims narrow it); audit events give **detection**.

## Capabilities

### New Capabilities
- `workload-identity`: trust policies for external OIDC issuers (GitHub Actions, Kubernetes), verified exchange of an external identity token for a short-lived agent token, and the audit trail.

### Modified Capabilities
None. The agent-token format, the gateway and `control-plane-api` auth for agents are unchanged; the new routes are additions.

## Out of scope
- AWS, GCP and Azure workload identity, SPIFFE/SPIRE, TLS-certificate identities (roadmap: SPIRE later).
- Non-GitHub CI issuers (GitLab, CircleCI, Buildkite): the policy model is generic OIDC, but only GitHub and Kubernetes are tested and documented here.
- The Kubernetes operator, CSI driver or sidecar injector (phase 5).
- Per-policy ABAC and Cedar (T2): matching here is claim conditions only.
- Letting a workload mint credentials for other agents, or any route that returns a stored secret value.

## Depends on
none. `t1-human-auth` (the `Needs` entry in the roadmap) is archived on main, so its human auth and generic JWKS verification are used as shipped and there is no unarchived dependency (`x-depends_on: []`). Nothing in the roadmap lists D4 in `Needs`, so there is no Contract task group.

## Impact
`services/control-plane` (migration, `workload.rs`, API routes, OpenAPI, audit codes), `crates/ls-audit` (event codes), `crates/smith-cli` (`login --workload`, doctor), `integrations/github-action`, `apps/web`, `apps/desktop`, `packages/control-plane-client`, `tests/e2e`, `tests/adversarial`, `justfile`, `docs/`.
