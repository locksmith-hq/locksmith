import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { UsersModule } from "../users/users.module.js";
import { AuditController } from "./audit.controller.js";
import { AuditReadsService } from "./audit-reads.service.js";

@Module({
  imports: [AuthModule, UsersModule],
  providers: [AuditReadsService, OrgBindingGuard],
  controllers: [AuditController],
})
export class AuditReadsModule {}
