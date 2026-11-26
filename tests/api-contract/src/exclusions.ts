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
    "t5-honey-tokens 2.3 is implemented but needs a bound principal (B6 principal resolution) and a core with a key service; scenarios arrive with t5 6.1",
  "POST /v1/projects/{project_id}/environments/{environment_id}/honey-tokens":
    "t5-honey-tokens 2.3 is implemented but needs a bound principal (B6 principal resolution) and a core with a key service; scenarios arrive with t5 6.1",
  "DELETE /v1/projects/{project_id}/environments/{environment_id}/honey-tokens/{id}":
    "t5-honey-tokens 2.3 is implemented but needs a bound principal (B6 principal resolution) and a core with a key service; scenarios arrive with t5 6.1",
  "POST /v1/projects/{project_id}/environments/{environment_id}/honey-tokens/{id}/disable":
    "t5-honey-tokens 2.3 is implemented but needs a bound principal (B6 principal resolution) and a core with a key service; scenarios arrive with t5 6.1",
  "POST /internal/v1/honey/mint":
    "service-token-only internal route; covered by services/control-plane/tests/honey_mint.rs",
};
