import { z } from "zod";
import { defineRoute, type RouteDef } from "../../openapi/build.js";

/** Closed set of notifiable events, mapped from audit kinds by the fan-out job (n1 design, decision 2). */
export const NotifyKind = z.enum(["relay.denied", "git.denied", "grant.revoked", "agent.deleted"]);
export type NotifyKind = z.infer<typeof NotifyKind>;

const NotifyChannel = z.enum(["inbox", "email", "slack"]);

/** Who receives a kind on a channel; `owner` is the only resolvable value until the T6 roles exist. */
const NotifyAudience = z.enum(["owner", "admins", "user"]);

/**
 * Allow-listed payload (decision 6): typed ledger fields only, never a copy of the event body, so no
 * secret value can reach a notification. Adding a field here is a deliberate, reviewed act.
 */
const NotificationPayload = z
  .object({
    kind: NotifyKind,
    actor: z.object({ id: z.string(), name: z.string() }).nullable(),
    object_name: z.string().nullable(),
    occurred_at: z.string(),
    link: z.string(),
  })
  .strict();

const Notification = z.object({
  id: z.uuid(),
  kind: NotifyKind,
  payload: NotificationPayload,
  created_at: z.string(),
  read_at: z.string().nullable(),
});

const NotificationPage = z.object({
  items: z.array(Notification),
  unread_count: z.number().int().min(0),
});

const NotificationRule = z.object({
  kind: NotifyKind,
  channel: NotifyChannel,
  audience: NotifyAudience,
  audience_user_id: z.uuid().nullable(),
});

const NotificationRules = z.object({ rules: z.array(NotificationRule) });

/** Email is a switch; Slack is shown as `configured` only, its webhook URL never reaches the API (decision 5). */
const NotificationChannels = z.object({
  email: z.object({ enabled: z.boolean() }),
  slack: z.object({ configured: z.boolean() }),
});

const NotificationChannelsUpdate = z.object({ email: z.object({ enabled: z.boolean() }) });

const NotificationTestResult = z.object({ state: z.enum(["queued", "sent", "failed"]) });

/** RFC 9457 problem body shared by every error response (B1 task 4.4 owns the filter). */
const Problem = z.object({ type: z.string(), title: z.string(), status: z.number().int(), detail: z.string() });

const idParams = z.object({ id: z.uuid() });

export const notificationRoutes: RouteDef[] = [
  defineRoute({
    method: "GET",
    path: "/v1/notifications",
    query: z.object({ unread: z.boolean().optional() }),
    responses: { 200: NotificationPage, 401: Problem },
  }),
  defineRoute({
    method: "POST",
    path: "/v1/notifications/{id}/read",
    params: idParams,
    responses: { 204: null, 401: Problem, 404: Problem },
  }),
  defineRoute({
    method: "POST",
    path: "/v1/notifications/read-all",
    responses: { 204: null, 401: Problem },
  }),
  defineRoute({
    method: "GET",
    path: "/v1/notification-rules",
    responses: { 200: NotificationRules, 401: Problem, 403: Problem },
  }),
  defineRoute({
    method: "PUT",
    path: "/v1/notification-rules",
    body: NotificationRules,
    responses: { 200: NotificationRules, 401: Problem, 403: Problem, 422: Problem },
  }),
  defineRoute({
    method: "GET",
    path: "/v1/notification-channels",
    responses: { 200: NotificationChannels, 401: Problem, 403: Problem },
  }),
  defineRoute({
    method: "PUT",
    path: "/v1/notification-channels",
    body: NotificationChannelsUpdate,
    responses: { 200: NotificationChannels, 401: Problem, 403: Problem, 422: Problem },
  }),
  defineRoute({
    method: "POST",
    path: "/v1/notification-channels/test",
    responses: { 200: NotificationTestResult, 401: Problem, 403: Problem },
  }),
];
