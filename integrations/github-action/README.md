# Locksmith login for GitHub Actions

Logs a job in to Locksmith with the job's own GitHub OIDC identity. There is no stored secret: no
enrollment secret and no long-lived token in repository or organization secrets. The action
installs a pinned `smith` release (SHA-256 checked against the release manifest) and runs
`smith login --workload github`, which asks the runner for an identity token, exchanges it at the
control plane for the ordinary 15-minute agent token of the agent named by the trust policy, and
writes only that agent token to `agent.json` (mode 0600). Later steps use `smith grants` and
`smith relay`; what they can reach is exactly the grants of that agent.

This is containment, not prevention: any code running in a job that matches the policy (including
a compromised dependency) can use those grants for 15 minutes. Pin the policy tightly and give the
agent narrow grants.

## Requirements

- The job needs `permissions: id-token: write`. Without it the runner does not provide
  `ACTIONS_ID_TOKEN_REQUEST_URL`, and the login fails with a message saying so.
- A workload identity (trust policy) in the console, with its handle `lsw_...` (not a secret). It
  must pin `repository`; add `ref` or `environment` as well. The policy audience defaults to the
  control plane URL, which is what this action requests unless you set `audience`.

## Example

```yaml
name: deploy
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write   # required: lets the job request its OIDC token

jobs:
  deploy:
    runs-on: ubuntu-24.04
    environment: production   # pin the policy to this environment too
    steps:
      - uses: locksmith-hq/locksmith/integrations/github-action@<commit-sha>   # pin a commit
        with:
          smith-version: "0.1.0"
          policy: lsw_REPLACE_WITH_THE_POLICY_HANDLE
          control-plane-url: https://api.locksmith.example.com
          gateway-url: https://gateway.locksmith.example.com
      - run: smith grants
      - run: smith relay --secret-id "$SECRET_ID" https://api.example.com/deploy -X POST
        env:
          SECRET_ID: 0191a3b2-7c1e-7a3f-8b2d-5e6f7a8b9c0d
```

A policy that matches the example pins the subject and the ref:

| Claim | Condition |
|---|---|
| `repository` | `acme/api` |
| `ref` | `refs/heads/main` |
| `environment` | `production` |

## Inputs

| Input | Required | Description |
|---|---|---|
| `policy` | yes | Policy handle `lsw_...`. |
| `control-plane-url` | yes | Control plane base URL (https). |
| `gateway-url` | yes | Gateway base URL (https). |
| `smith-version` | yes | Release to install; pin it. |
| `audience` | no | Audience to request; must equal the policy audience (default: the control plane URL). |

Runners: Linux and macOS (x86_64 and arm64). The action prints nothing but a login status line and
never prints a token.
