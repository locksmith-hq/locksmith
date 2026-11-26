import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { SessionController } from "./session.controller.js";
import { UsersService } from "./users.service.js";

@Module({
  imports: [AuthModule],
  providers: [UsersService],
  controllers: [SessionController],
  exports: [UsersService],
})
export class UsersModule {}
