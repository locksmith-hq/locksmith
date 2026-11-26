import { Inject, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { z } from "zod";
import { TenantService } from "../../tenant/tenant.service.js";
import { NotificationPayload, type NotificationPage } from "./notification.schemas.js";

/** Newest items returned per request; `unread_count` always counts every unread item. */
const INBOX_PAGE_SIZE = 100;

/** Re-parses the stored payload through the allow-list so no extra stored field can reach a response. */
const AllowListedPayload = z.object(NotificationPayload.shape);

type Page = z.infer<typeof NotificationPage>;

/** The caller's inbox. Every query runs in the request's tenant transaction and filters by org and user. */
@Injectable()
export class NotificationsService {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  private caller(): { orgId: string; userId: string } {
    const orgId = this.tenant.orgId();
    const userId = this.tenant.userId();
    if (!orgId || !userId) throw new UnauthorizedException();
    return { orgId, userId };
  }

  async list(unreadOnly: boolean): Promise<Page> {
    const { orgId, userId } = this.caller();
    const tx = this.tenant.tx();
    let q = tx
      .selectFrom("notifications")
      .select(["id", "kind", "payload", "created_at", "read_at"])
      .where("org_id", "=", orgId)
      .where("user_id", "=", userId);
    if (unreadOnly) q = q.where("read_at", "is", null);
    const rows = await q.orderBy("created_at", "desc").orderBy("id", "desc").limit(INBOX_PAGE_SIZE).execute();
    const unread = await tx
      .selectFrom("notifications")
      .select((eb) => eb.fn.countAll<string>().as("n"))
      .where("org_id", "=", orgId)
      .where("user_id", "=", userId)
      .where("read_at", "is", null)
      .executeTakeFirstOrThrow();
    return {
      items: rows.map((r) => ({
        id: r.id,
        kind: r.kind as Page["items"][number]["kind"],
        payload: AllowListedPayload.parse(r.payload),
        created_at: r.created_at.toISOString(),
        read_at: r.read_at ? r.read_at.toISOString() : null,
      })),
      unread_count: Number(unread.n),
    };
  }

  /** Marks one of the caller's items read; idempotent. Another user's or org's id is a 404. */
  async markRead(id: string): Promise<void> {
    const { orgId, userId } = this.caller();
    const tx = this.tenant.tx();
    await tx
      .updateTable("notifications")
      .set({ read_at: new Date() })
      .where("id", "=", id)
      .where("org_id", "=", orgId)
      .where("user_id", "=", userId)
      .where("read_at", "is", null)
      .execute();
    const owned = await tx
      .selectFrom("notifications")
      .select("id")
      .where("id", "=", id)
      .where("org_id", "=", orgId)
      .where("user_id", "=", userId)
      .executeTakeFirst();
    if (!owned) throw new NotFoundException();
  }

  async markAllRead(): Promise<void> {
    const { orgId, userId } = this.caller();
    await this.tenant
      .tx()
      .updateTable("notifications")
      .set({ read_at: new Date() })
      .where("org_id", "=", orgId)
      .where("user_id", "=", userId)
      .where("read_at", "is", null)
      .execute();
  }
}
