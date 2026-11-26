import {
  BadRequestException,
  Controller,
  Get,
  HttpCode,
  Inject,
  NotImplementedException,
  Param,
  Post,
  Put,
  Query,
} from "@nestjs/common";
import { z } from "zod";
import { NotificationsService } from "./notifications.service.js";

const UnreadQuery = z.enum(["true", "false"]).optional();
const IdParam = z.uuid();

/** Inbox routes are live (n1 4.1); rules and channels stay 501 contract stubs until their tasks land. */
@Controller("v1")
export class NotificationsController {
  constructor(@Inject(NotificationsService) private readonly notifications: NotificationsService) {}

  @Get("notifications")
  list(@Query("unread") unread?: string) {
    const parsed = UnreadQuery.safeParse(unread);
    if (!parsed.success) throw new BadRequestException("unread must be true or false");
    return this.notifications.list(parsed.data === "true");
  }

  @Post("notifications/read-all")
  @HttpCode(204)
  async readAll(): Promise<void> {
    await this.notifications.markAllRead();
  }

  @Post("notifications/:id/read")
  @HttpCode(204)
  async read(@Param("id") id: string): Promise<void> {
    if (!IdParam.safeParse(id).success) throw new BadRequestException("id must be a uuid");
    await this.notifications.markRead(id);
  }

  @Get("notification-rules")
  rules(): never {
    throw new NotImplementedException();
  }

  @Put("notification-rules")
  putRules(): never {
    throw new NotImplementedException();
  }

  @Get("notification-channels")
  channels(): never {
    throw new NotImplementedException();
  }

  @Put("notification-channels")
  putChannels(): never {
    throw new NotImplementedException();
  }

  @Post("notification-channels/test")
  testChannel(): never {
    throw new NotImplementedException();
  }
}
