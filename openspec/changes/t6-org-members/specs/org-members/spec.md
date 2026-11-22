# Spec Delta

## Purpose
Team organizations, membership, invites and roles for human users.

## ADDED Requirements

### Requirement: Membership decides which org a human may act in
The control plane SHALL bind a human request to the org named by `X-Locksmith-Org` only when the verified user has a membership in it, and to the personal org when the header is absent. It SHALL NOT trust the header alone and SHALL answer an org the caller is not a member of with the same `404` as an org that does not exist.

#### Scenario: Member selects a team org
- **WHEN** a member sends a valid token and `X-Locksmith-Org` of a team org they belong to
- **THEN** the handler sees that org's binding and the caller's role

#### Scenario: Non-member selects an org
- **WHEN** a signed-in user names an org they have no membership in
- **THEN** the response is `404` and no row of that org is read

#### Scenario: Existing users keep working
- **WHEN** a user created before this change signs in with no header
- **THEN** they act in their personal org as `owner`

### Requirement: Team orgs
A signed-in user SHALL be able to create a team org (becoming its `owner`), list the orgs they belong to, rename an org they own or administer, and delete an org they own that holds no secrets.

#### Scenario: Create and list
- **WHEN** a user creates an org named "Acme"
- **THEN** it appears in their list with role `owner` and an `org.created` ledger event is written

#### Scenario: Delete a non-empty org
- **WHEN** an owner deletes an org that still has secrets
- **THEN** the response is `409` and nothing is deleted

### Requirement: Invites are single-use, expiring and stored hashed
An owner or admin SHALL be able to invite an email with a role of `admin` or `member` (only an owner may invite an `owner`). The API SHALL return the invite link exactly once and store only its SHA-256. An invite SHALL be accepted only by a signed-in user whose verified email equals the invited address, once, before its expiry.

#### Scenario: Accept
- **WHEN** the invited user, signed in with that verified email, opens the link
- **THEN** they become a member with the invited role and the invite cannot be used again

#### Scenario: Wrong, unverified, expired, revoked or reused
- **WHEN** the link is opened by a different or unverified email, after expiry, after revocation, or a second time
- **THEN** the response is a uniform `404` that does not say which case applied, and no membership is created

#### Scenario: Link never stored or logged
- **WHEN** the leak scan runs after an invite flow
- **THEN** neither the database, the ledger nor any log contains the invite token or link

### Requirement: Roles and the last owner
Roles SHALL be `owner`, `admin` and `member`. Owners and admins SHALL manage members; only an owner SHALL change an owner's role, promote to `owner` or delete the org; a member SHALL only read the member list and leave. The org SHALL always keep at least one owner.

#### Scenario: Member cannot manage
- **WHEN** a `member` invites, removes or changes a role
- **THEN** the response is `403` problem details

#### Scenario: Last owner protected
- **WHEN** the only owner tries to leave, is removed or is demoted
- **THEN** the response is `409` and membership is unchanged, including under two concurrent attempts by two owners

### Requirement: Membership changes are audited and revoke nothing silently
Every membership and invite change SHALL append a ledger event without credentials. Removing a member SHALL take effect on their next request (no cached binding outlives the membership beyond the access token's own lifetime check).

#### Scenario: Removed member
- **WHEN** a member is removed and sends a request that names that org
- **THEN** it is refused with `404`

### Requirement: Tenant isolation covers the new tables
`memberships` and `invites` SHALL have `org_id`, forced row-level security and no `BYPASSRLS` access, and `ls-tenant-lint` SHALL cover them.

#### Scenario: Cross-org read
- **WHEN** a transaction bound to org A selects from either table
- **THEN** it sees no row of org B
