import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { UsersModule } from "../users/users.module.js";
import { AuditController } from "./audit.controller.js";
import { AuditService } from "./audit.service.js";

@Module({
  imports: [AuthModule, UsersModule],
  providers: [AuditService, OrgBindingGuard],
  controllers: [AuditController],
})
export class AuditReadModule {}
