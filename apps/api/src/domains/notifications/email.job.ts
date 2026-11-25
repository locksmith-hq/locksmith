import { Inject, Injectable, Logger, type OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createTransport, type Transporter } from "nodemailer";
import { PgBoss } from "pg-boss";
import { KYSELY, type Database } from "../../db/db.module.js";
import { PG_BOSS } from "../../jobs/jobs.service.js";
import { TenantService } from "../../tenant/tenant.service.js";
import type { Payload } from "./fanout.job.js";

const EMAIL_QUEUE = "notify.email";
const INTERVAL_SECONDS = 2;
/** Final failure after this many sends (N1 task 5.1: `retryLimit 5`). */
export const MAX_ATTEMPTS = 5;
/** Per-org cap (N1 task 5.1); deliveries over it wait for the next minute. */
export const ORG_CAP_PER_MINUTE = 60;
const BATCH = 100;

export type EmailConfig = { host: string; port: number; from: string };

/** Fixed slugs only: provider text never reaches a row, a log or a response (N1 decision 7). */
export type EmailErrorCode = "email.smtp_unreachable" | "email.smtp_rejected" | "email.no_recipient";

export function classify(err: unknown): EmailErrorCode {
  const code = (err as { responseCode?: number } | null)?.responseCode;
  return typeof code === "number" && code >= 500 ? "email.smtp_rejected" : "email.smtp_unreachable";
}

/** A fixed text built from the allow-listed payload fields only (design decision 6). */
export function renderEmail(p: Payload): { subject: string; text: string } {
  const what = p.object_name ? ` on ${p.object_name}` : "";
  const who = p.actor ? ` by ${p.actor.name}` : "";
  return {
    subject: `Locksmith: ${p.kind}`,
    text: `${p.kind}${what}${who} at ${p.occurred_at}.\nOpen: ${p.link}\n`,
  };
}

export interface DeliveryOutcome {
  sent: number;
  retried: number;
  failed: number;
  deferred: number;
}

/**
 * Email delivery (N1 5.1): picks up `pending` email rows per org, sends through the SMTP relay and
 * records the fixed outcome on the delivery row. Retries with backoff up to MAX_ATTEMPTS, then marks
 * the row failed with a slug.
 */
@Injectable()
export class EmailDeliveryJob implements OnModuleInit {
  private readonly log = new Logger(EmailDeliveryJob.name);
  private readonly sentAt = new Map<string, number[]>();
  private readonly notBefore = new Map<string, number>();
  private transport: Transporter | null = null;
  private cfg: EmailConfig | null = null;
  /** Overridable by tests; not injected. */
  backoffMs: (attempts: number) => number = (n) => 2 ** n * 1000;
  now: () => number = Date.now;

  constructor(
    @Inject(KYSELY) private readonly db: Database,
    @Inject(TenantService) private readonly tenant: TenantService,
    @Inject(PG_BOSS) private readonly boss: PgBoss,
    @Inject(ConfigService) config: ConfigService,
  ) {
    const host = config.get<string>("SMTP_HOST");
    const port = config.get<number>("SMTP_PORT");
    const from = config.get<string>("SMTP_FROM");
    if (host && port && from) this.configure({ host, port, from });
  }

  configure(cfg: EmailConfig): void {
    this.cfg = cfg;
    this.transport = createTransport({ host: cfg.host, port: cfg.port, secure: false, ignoreTLS: true, connectionTimeout: 5000, socketTimeout: 5000 });
  }

  async onModuleInit(): Promise<void> {
    if (!this.cfg) {
      this.log.warn("email delivery disabled: SMTP_HOST, SMTP_PORT and SMTP_FROM are not all set");
      return;
    }
    await this.boss.createQueue(EMAIL_QUEUE);
    await this.boss.work(EMAIL_QUEUE, async () => {
      try {
        await this.runOnce();
      } finally {
        await this.boss.send(EMAIL_QUEUE, {}, { startAfter: INTERVAL_SECONDS, singletonKey: EMAIL_QUEUE });
      }
    });
    await this.boss.schedule(EMAIL_QUEUE, "* * * * *", {}, { singletonKey: EMAIL_QUEUE });
  }

  async runOnce(): Promise<DeliveryOutcome> {
    const total: DeliveryOutcome = { sent: 0, retried: 0, failed: 0, deferred: 0 };
    if (!this.cfg || !this.transport) return total;
    const orgs = await this.db.selectFrom("notification_cursors").select("org_id").execute();
    for (const { org_id } of orgs) {
      try {
        const o = await this.processOrg(org_id);
        total.sent += o.sent;
        total.retried += o.retried;
        total.failed += o.failed;
        total.deferred += o.deferred;
      } catch (err) {
        this.log.error(`email delivery failed for one org: ${err instanceof Error ? err.name : "error"}`);
      }
    }
    return total;
  }

  private async processOrg(orgId: string): Promise<DeliveryOutcome> {
    const out: DeliveryOutcome = { sent: 0, retried: 0, failed: 0, deferred: 0 };
    const now = this.now();
    const window = (this.sentAt.get(orgId) ?? []).filter((t) => now - t < 60_000);
    this.sentAt.set(orgId, window);
    const rows = await this.tenant.run(orgId, (tx) =>
      tx
        .selectFrom("notification_deliveries as d")
        .innerJoin("notifications as n", "n.id", "d.notification_id")
        .innerJoin("users as u", "u.id", "n.user_id")
        .select(["d.id", "d.attempts", "n.payload", "u.email"])
        .where("d.org_id", "=", orgId)
        .where("d.channel", "=", "email")
        .where("d.state", "=", "pending")
        .orderBy("d.created_at")
        .limit(BATCH)
        .execute(),
    );
    for (const r of rows) {
      if ((this.notBefore.get(r.id) ?? 0) > now) continue;
      if (window.length >= ORG_CAP_PER_MINUTE) {
        out.deferred += 1;
        continue;
      }
      if (!r.email) {
        await this.record(orgId, r.id, "failed", r.attempts, "email.no_recipient");
        out.failed += 1;
        continue;
      }
      const payload = (typeof r.payload === "string" ? JSON.parse(r.payload) : r.payload) as Payload;
      const msg = renderEmail(payload);
      try {
        await this.transport!.sendMail({ from: this.cfg!.from, to: r.email, subject: msg.subject, text: msg.text });
        window.push(now);
        await this.record(orgId, r.id, "sent", r.attempts + 1, null);
        this.notBefore.delete(r.id);
        out.sent += 1;
      } catch (err) {
        const code = classify(err);
        const attempts = r.attempts + 1;
        if (attempts >= MAX_ATTEMPTS || code === "email.smtp_rejected") {
          await this.record(orgId, r.id, "failed", attempts, code);
          this.notBefore.delete(r.id);
          out.failed += 1;
        } else {
          await this.record(orgId, r.id, "pending", attempts, code);
          this.notBefore.set(r.id, now + this.backoffMs(attempts));
          out.retried += 1;
        }
      }
    }
    return out;
  }

  private record(orgId: string, id: string, state: "pending" | "sent" | "failed", attempts: number, code: EmailErrorCode | null) {
    return this.tenant.run(orgId, (tx) =>
      tx.updateTable("notification_deliveries").set({ state, attempts, last_error_code: code }).where("id", "=", id).execute(),
    );
  }
}
