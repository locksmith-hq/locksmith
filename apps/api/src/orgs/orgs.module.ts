import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { UsersModule } from "../users/users.module.js";
import { OrgsController } from "./orgs.controller.js";
import { OrgsService } from "./orgs.service.js";

@Module({
  imports: [AuthModule, UsersModule],
  providers: [OrgsService, OrgBindingGuard],
  controllers: [OrgsController],
})
export class OrgsModule {}
