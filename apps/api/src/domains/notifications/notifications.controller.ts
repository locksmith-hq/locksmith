import { Controller, Get, NotImplementedException, Post, Put } from "@nestjs/common";

/** Contract stubs (n1 group 1): every route answers 501 until the inbox and rules API lands (group 4). */
@Controller("v1")
export class NotificationsController {
  @Get("notifications")
  list(): never {
    throw new NotImplementedException();
  }

  @Post("notifications/read-all")
  readAll(): never {
    throw new NotImplementedException();
  }

  @Post("notifications/:id/read")
  read(): never {
    throw new NotImplementedException();
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
