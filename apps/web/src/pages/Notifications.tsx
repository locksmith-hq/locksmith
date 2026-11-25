import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Head } from "@locksmith/ui";
import {
  NOTIFICATION_CHANNELS,
  NOTIFICATION_KINDS,
  notificationKindLabel,
  notificationSummary,
  toggleRule,
  ApiError,
  type Client,
  type NotificationChannel,
  type NotificationKind,
} from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");
export const INBOX_KEY = ["notifications"] as const;

/** Bell with the unread count for the top bar. A failed poll shows no count rather than a wrong one. */
export function NotificationBell({ client }: { client: Client }) {
  const q = useQuery({ queryKey: INBOX_KEY, queryFn: () => client.listNotifications(), refetchInterval: 30_000 });
  const n = q.data?.unread_count ?? 0;
  return (
    <Link to="/notifications" className="shell-bell" aria-label={n ? `Notifications, ${n} unread` : "Notifications"}>
      <span aria-hidden="true">🔔</span>
      {n > 0 && (
        <span className="shell-bell-count" data-testid="unread-count">
          {n}
        </span>
      )}
    </Link>
  );
}

/** The signed-in user's inbox: own items only (the API scopes them). */
export function Inbox({ client }: { client: Client }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: INBOX_KEY, queryFn: () => client.listNotifications() });
  const refresh = () => qc.invalidateQueries({ queryKey: INBOX_KEY });
  const read = useMutation({ mutationFn: (id: string) => client.markNotificationRead(id), onSuccess: refresh });
  const readAll = useMutation({ mutationFn: () => client.markAllNotificationsRead(), onSuccess: refresh });
  const failed = read.error ?? readAll.error;
  return (
    <section aria-label="Notifications">
      <Head title="Notifications" />
      {failed != null && (
        <p role="alert" className="state">
          {errMsg(failed)}
        </p>
      )}
      <QueryState query={q} isEmpty={(d) => d.items.length === 0} empty="No notifications.">
        {(d) => (
          <>
            <p>
              {d.unread_count} unread{" "}
              <button className="btn sm" disabled={d.unread_count === 0} onClick={() => readAll.mutate()}>
                Mark all read
              </button>{" "}
              <Link to="/settings/notifications">Settings</Link>
            </p>
            <ul className="plain">
              {d.items.map((n) => (
                <li key={n.id} aria-label={notificationSummary(n)} data-unread={n.read_at === null}>
                  <strong>{notificationSummary(n)}</strong> <time dateTime={n.created_at}>{n.created_at}</time>{" "}
                  <Link to={n.payload.link}>View</Link>{" "}
                  {n.read_at === null && (
                    <button className="btn sm quiet" onClick={() => read.mutate(n.id)}>
                      Mark read: {notificationSummary(n)}
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}
      </QueryState>
    </section>
  );
}

/** Rules matrix, email switch and Slack state. Owners only: others see a notice and no controls. */
export function NotificationSettings({ client }: { client: Client }) {
  const qc = useQueryClient();
  const rules = useQuery({ queryKey: ["notification-rules"], queryFn: () => client.getNotificationRules() });
  const channels = useQuery({ queryKey: ["notification-channels"], queryFn: () => client.getNotificationChannels() });
  const setRules = useMutation({
    mutationFn: (next: Parameters<Client["setNotificationRules"]>[0]) => client.setNotificationRules(next),
    onSuccess: (d) => qc.setQueryData(["notification-rules"], d),
  });
  const setEmail = useMutation({
    mutationFn: (on: boolean) => client.setEmailChannel(on),
    onSuccess: (d) => qc.setQueryData(["notification-channels"], d),
  });
  if (rules.error instanceof ApiError && rules.error.status === 403)
    return (
      <section aria-label="Notification settings">
        <Head title="Notification settings" />
        <p>Only an organization owner can change notification settings.</p>
      </section>
    );
  const failed = setRules.error ?? setEmail.error;
  const slack = channels.data?.slack.configured ?? false;
  return (
    <section aria-label="Notification settings">
      <Head title="Notification settings" />
      {failed != null && (
        <p role="alert" className="state">
          {errMsg(failed)}
        </p>
      )}
      <QueryState query={channels}>
        {(c) => (
          <p>
            <label>
              <input
                type="checkbox"
                checked={c.email.enabled}
                disabled={setEmail.isPending}
                onChange={(e) => setEmail.mutate(e.target.checked)}
              />{" "}
              Email delivery
            </label>{" "}
            Slack: {c.slack.configured ? "configured" : "not configured"}
          </p>
        )}
      </QueryState>
      <QueryState query={rules}>
        {(d) => (
          <table className="grid" aria-label="Notification rules">
            <thead>
              <tr>
                <th>Event</th>
                {NOTIFICATION_CHANNELS.map((ch) => (
                  <th key={ch}>{ch}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {NOTIFICATION_KINDS.map((k: NotificationKind) => (
                <tr key={k}>
                  <td>{notificationKindLabel(k)}</td>
                  {NOTIFICATION_CHANNELS.map((ch: NotificationChannel) => (
                    <td key={ch}>
                      <input
                        type="checkbox"
                        aria-label={`${notificationKindLabel(k)} to ${ch}`}
                        checked={d.rules.some((r) => r.kind === k && r.channel === ch)}
                        disabled={setRules.isPending || (ch === "slack" && !slack)}
                        onChange={() => setRules.mutate(toggleRule(d.rules, k, ch))}
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </QueryState>
    </section>
  );
}
