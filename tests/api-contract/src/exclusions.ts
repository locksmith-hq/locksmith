// Paths with no scenario yet, each with the reason it is excluded. A scenario file that covers a
// path must delete its row here: the coverage test fails on a row that is already covered.
export const EXCLUDED: Record<string, string> = {
  "DELETE /v1/orgs/current/invites/{invite_id}":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
  "DELETE /v1/orgs/current/members/{user_id}":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
  "DELETE /v1/orgs/{org_id}":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
  "GET /v1/orgs":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
  "GET /v1/orgs/current/invites":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
  "GET /v1/orgs/current/members":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
  "PATCH /v1/orgs/current/members/{user_id}":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
  "PATCH /v1/orgs/{org_id}":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
  "POST /v1/invites/accept":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
  "POST /v1/orgs/current/invites":
    "t6-org-members group 1 adds the contract only; the handler and its scenario land in the later t6 task groups",
};
