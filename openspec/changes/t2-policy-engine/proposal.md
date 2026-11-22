# Proposal: T2 policy engine (RBAC, ABAC and usage modes)

## Why
After T6 an org has owners, admins and members, but every route except member management still lets any member do anything (T6 proposal, "Role contract for T2"). Agent grants have one mode, `relay` (`GrantMode` in `services/control-plane/src/api/agents.rs`), although the product already has delegated paths (`smith git`, `smith aws`, `smith db`) and human-only injection (`smith run`). Teams need a single, auditable answer to "who or which agent may do what to which secret, in which environment, and how". T4 (access requests) builds on this change's contract.

## What Changes
- **`ls-policy` crate.** Wraps `cedar-policy` in-process: one Cedar schema (principals `User`, `Agent`; resources `Org`, `Project`, `Environment`, `Secret`; actions for human API operations and for the three agent usage modes) and a `decide(principal, action, resource, context) -> Decision` call that returns allow/deny plus the ids of the policies that decided it.
- **Built-in role policies (RBAC).** Fixed, versioned Cedar policies for `owner`, `admin` and `member` that encode today's behaviour plus the T6 role rules: members read metadata and use what they are granted; admins manage projects, environments, secrets, agents and grants; owners also manage the org and its policies.
- **Org policies (ABAC).** Owners add Cedar policies of their own (for example "no agent may use secrets in the environment named `production` outside 09:00-18:00", or "only admins write to `prod`"). Each is validated against the schema before it is stored, versioned, and every change is a ledger event. Built-in `forbid` policies cannot be overridden.
- **Usage modes per grant.** `GrantMode` gains `delegate` (the gateway or `locksmithd` acts with a short-lived scoped credential: git, AWS STS, DB relay) and `inject` (the value is placed into a process environment by `smith run`). A built-in `forbid` makes `inject` impossible for any `Agent` principal, so agents still never receive a value.
- **Enforcement.** The control plane asks `ls-policy` on every mutating and secret-reading route (replacing "any member acts"); the gateway asks it (through the grants it already fetches) before relay and delegated use. A deny is a `403` with a fixed problem slug and no policy text.
- **Explain.** `POST /v1/policies/check` answers "would this be allowed, and by which policies" for the console and CLI, without performing the action.
- **Console and desktop.** A Policies page (built-in policies read-only, org policies editable by owners with inline validation errors, a "check access" form) and the grant form gains a mode picker. Desktop shows the same Policies page and mode picker.

## Out of scope
- Access requests, approvals and time-boxed grants (T4).
- Groups or teams inside an org, SAML/SCIM attributes, custom roles beyond owner/admin/member.
- A policy language other than Cedar, or an out-of-process authorizer (OPA, OpenFGA, SpiceDB).
- Policy on the gateway's local bindings file (`locksmithd` single-user mode stays as is).

## Depends on
`t6-org-members:contract` (the `OrgRole` type and memberships). Groups after the contract need T6 groups 2 and 3 (memberships table and `OrgBinding` exposing the role), which are already ticked on `claude/change-t6-org-members`.

## Usable outcome
An org owner sees which built-in rules apply to owners, admins and members, adds a Cedar policy that limits agents in `production`, grants an agent `delegate` use of a secret, and asks "can agent X relay secret Y now?" and gets a yes/no with the deciding policies. A member who tries an admin action gets `403`, and nobody can give an agent `inject`.
