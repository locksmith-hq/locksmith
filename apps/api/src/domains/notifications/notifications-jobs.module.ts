import { Module } from "@nestjs/common";
import { JobsModule } from "../../jobs/jobs.module.js";
import { EmailDeliveryJob } from "./email.job.js";
import { FanoutJob } from "./fanout.job.js";

/** Background jobs of the notifications domain; kept apart from the controllers so route tests need no database. */
@Module({ imports: [JobsModule], providers: [FanoutJob, EmailDeliveryJob] })
export class NotificationsJobsModule {}
