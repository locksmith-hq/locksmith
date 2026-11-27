import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { UsersModule } from "../users/users.module.js";
import { ProjectsController } from "./projects.controller.js";
import { ProjectsService } from "./projects.service.js";

@Module({
  imports: [AuthModule, UsersModule],
  providers: [ProjectsService, OrgBindingGuard],
  controllers: [ProjectsController],
})
export class ProjectsModule {}
