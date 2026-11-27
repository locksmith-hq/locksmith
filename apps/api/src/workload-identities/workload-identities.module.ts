import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { UsersModule } from "../users/users.module.js";
import { WorkloadIdentitiesController } from "./workload-identities.controller.js";
import { WorkloadTokensController } from "./workload-tokens.controller.js";
import { WorkloadTokensService } from "./workload-tokens.service.js";
import { WorkloadIdentitiesService } from "./workload-identities.service.js";

@Module({
  imports: [AuthModule, UsersModule],
  providers: [WorkloadIdentitiesService, WorkloadTokensService, OrgBindingGuard],
  controllers: [WorkloadIdentitiesController, WorkloadTokensController],
})
export class WorkloadIdentitiesModule {}
