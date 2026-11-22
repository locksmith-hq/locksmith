# Proposal: T6 organizations and members

## Why
After T1 every person has exactly one org, their personal one, and is its only owner (`users.personal_org_id`). A team cannot share secrets, agents or grants. T2 (policy) needs roles to exist before it can decide who may do what, and N1 needs members to notify. T6 adds team orgs, membership, invites and the three roles.

## What Changes
- **Memberships.** A `memberships` table (org, user, role `owner|admin|member`) replaces "the user's one org" as the source of truth. Every existing user gets an `owner` membership of their personal org by migration, so nothing changes for current users.
- **Org selection.** A signed-in request names the org it acts in with `X-Locksmith-Org`; the control plane accepts it only if the verified user is a member. Absent header means the personal org (T1 behaviour, unchanged).
- **Team orgs.** `POST /v1/orgs` (replaces the dev-only create for humans) creates a team org with the caller as `owner`; list my orgs; rename; delete (owner only, refused while it still holds secrets).
- **Invites.** An owner or admin invites an email with a role. The API returns a single-use invite link once; only its SHA-256 is stored. The invitee accepts while signed in with a verified email equal to the invited one. Invites expire (7 days) and can be revoked.
- **Member management.** List members; change a role; remove a member; leave an org. The last owner can never leave, be removed or be demoted.
- **Role contract for T2.** Roles are exposed in the API and in a shared `OrgRole` type. T6 enforces only member management; all other routes keep today's rule (any member acts) until T2 lands.
- **Audit.** `org.created`, `member.invited`, `invite.accepted`, `invite.revoked`, `member.role_changed`, `member.removed`, `member.left` are ledger events (no tokens, no invite links).
- **Console and desktop.** An org switcher (backed by real memberships), a Members page (list, invite, role, remove), an Accept-invite route, and a "Leave org" action in `apps/web` and `apps/desktop`.

## Out of scope
- Sending the invite email: T6 returns the link for the inviter to copy; N1 (notifications) later delivers it by email and Slack.
- Policy, RBAC and ABAC on secrets, agents and grants (T2); SAML/SCIM; teams or groups inside an org.
- Billing seats, and transferring ownership by any path other than promoting another member to owner.
- Cross-org data sharing; agent identities stay single-org.

## Depends on
`t1-human-auth` (archived) and `t3-console-mvp` (pages and org header). Tasks 5.x and 6.x stack on `t3-console-mvp`; groups 1 to 4 do not need it.

## Usable outcome
A person creates a team org, invites a colleague by link, the colleague accepts with the same verified email and switches into the org, and an owner or admin can change roles, remove people, and nobody can strand an org without an owner.
