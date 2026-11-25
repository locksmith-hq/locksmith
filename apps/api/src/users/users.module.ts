import { Module } from "@nestjs/common";
import { AUDIT_SINK, FailClosedAuditSink } from "../audit/audit-sink.js";
import { AuthModule } from "../auth/auth.module.js";
import { SessionController } from "./session.controller.js";
import { UsersService } from "./users.service.js";

@Module({
  imports: [AuthModule],
  providers: [UsersService, { provide: AUDIT_SINK, useClass: FailClosedAuditSink }],
  controllers: [SessionController],
  exports: [UsersService],
})
export class UsersModule {}
