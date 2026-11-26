// Paths with no scenario yet, each with the reason it is excluded. A scenario file that covers a
// path must delete its row here: the coverage test fails on a row that is already covered.
export const EXCLUDED: Record<string, string> = {
  "GET /v1/notifications": "n1-notifications group 1 stub answers 501; scenarios arrive with group 4",
  "POST /v1/notifications/{id}/read": "n1-notifications group 1 stub answers 501; scenarios arrive with group 4",
  "POST /v1/notifications/read-all": "n1-notifications group 1 stub answers 501; scenarios arrive with group 4",
  "GET /v1/notification-rules": "n1-notifications group 1 stub answers 501; scenarios arrive with group 4",
  "PUT /v1/notification-rules": "n1-notifications group 1 stub answers 501; scenarios arrive with group 4",
  "GET /v1/notification-channels": "n1-notifications group 1 stub answers 501; scenarios arrive with group 4",
  "PUT /v1/notification-channels": "n1-notifications group 1 stub answers 501; scenarios arrive with group 4",
  "POST /v1/notification-channels/test": "n1-notifications group 1 stub answers 501; scenarios arrive with group 4",
  "GET /v1/projects/{project_id}/environments/{environment_id}/honey-tokens":
    "t5-honey-tokens group 1 stub answers 501; scenarios arrive with group 2",
  "POST /v1/projects/{project_id}/environments/{environment_id}/honey-tokens":
    "t5-honey-tokens group 1 stub answers 501; scenarios arrive with group 2",
  "DELETE /v1/projects/{project_id}/environments/{environment_id}/honey-tokens/{id}":
    "t5-honey-tokens group 1 stub answers 501; scenarios arrive with group 2",
  "POST /v1/projects/{project_id}/environments/{environment_id}/honey-tokens/{id}/disable":
    "t5-honey-tokens group 1 stub answers 501; scenarios arrive with group 2",
  "POST /internal/v1/honey/mint": "t5-honey-tokens group 1 contract only (answers 501); scenarios arrive with task 2.2",
};
