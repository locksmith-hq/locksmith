import { Inject, Injectable, Logger, type OnApplicationShutdown, type OnModuleInit } from "@nestjs/common";
import { PgBoss, type Job } from "pg-boss";

/** Injection token for the `pg-boss` instance (Postgres-backed queue, no Redis). */
export const PG_BOSS = Symbol("PG_BOSS");

/** Name of the example recurring job. */
export const HEARTBEAT_QUEUE = "system.heartbeat";
/** Every five minutes. */
export const HEARTBEAT_CRON = "*/5 * * * *";

export function createBoss(connectionString: string): PgBoss {
  if (!connectionString) throw new Error("jobs database url is empty");
  return new PgBoss({ connectionString, schema: "pgboss" });
}

/**
 * Starts pg-boss, declares queues and registers the recurring example job. Job payloads must never
 * carry plaintext secrets: pass ids and look the data up in the handler.
 */
@Injectable()
export class JobsService implements OnModuleInit, OnApplicationShutdown {
  private readonly log = new Logger(JobsService.name);
  /** Number of heartbeat jobs processed since start (observable in tests and metrics). */
  heartbeats = 0;

  constructor(@Inject(PG_BOSS) private readonly boss: PgBoss) {}

  async onModuleInit(): Promise<void> {
    this.boss.on("error", (err: Error) => this.log.error(`pg-boss: ${err.message}`));
    await this.boss.start();
    await this.boss.createQueue(HEARTBEAT_QUEUE);
    await this.boss.work(HEARTBEAT_QUEUE, (jobs: Job[]) => this.handleHeartbeat(jobs));
    await this.boss.schedule(HEARTBEAT_QUEUE, HEARTBEAT_CRON);
  }

  async handleHeartbeat(jobs: Job[]): Promise<void> {
    this.heartbeats += jobs.length;
    this.log.debug(`heartbeat x${jobs.length}`);
  }

  /** Enqueue one job now (also how tests trigger the recurring job without waiting for cron). */
  async enqueueHeartbeat(): Promise<string | null> {
    return this.boss.send(HEARTBEAT_QUEUE, {});
  }

  async onApplicationShutdown(): Promise<void> {
    await this.boss.stop({ graceful: true, timeout: 10_000 });
  }
}
