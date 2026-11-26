import { Controller, Delete, Get, NotImplementedException, Post } from "@nestjs/common";

/** Contract stubs (t5 group 1): every route answers 501 until the module lands (group 2). */
@Controller("v1/projects/:projectId/environments/:environmentId/honey-tokens")
export class HoneyTokensController {
  @Get()
  list(): never {
    throw new NotImplementedException();
  }

  @Post()
  create(): never {
    throw new NotImplementedException();
  }

  @Post(":id/disable")
  disable(): never {
    throw new NotImplementedException();
  }

  @Delete(":id")
  remove(): never {
    throw new NotImplementedException();
  }
}
