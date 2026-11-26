import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HEARTBEAT_CRON, HEARTBEAT_QUEUE, JobsService, createBoss } from "./jobs.service.js";

// Task 2.6: pg-boss against a real Postgres (Docker). No Redis anywhere.
let container: StartedTestContainer;
let service: JobsService;
let url: string;

beforeAll(async () => {
  container = await new GenericContainer("postgres:18.7")
    .withEnvironment({ POSTGRES_PASSWORD: "jobs-test-only" })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .start();
  url = `postgres://postgres:jobs-test-only@${container.getHost()}:${container.getMappedPort(5432)}/postgres`;
  service = new JobsService(createBoss(url));
  await service.onModuleInit();
}, 180_000);

afterAll(async () => {
  await service?.onApplicationShutdown();
  await container?.stop();
});

describe("jobs (pg-boss on Postgres)", () => {
  it("registers the recurring job schedule", async () => {
    const boss = createBoss(url);
    await boss.start();
    const schedules = await boss.getSchedules();
    await boss.stop({ graceful: true });
    const hb = schedules.find((s) => s.name === HEARTBEAT_QUEUE);
    expect(hb?.cron).toBe(HEARTBEAT_CRON);
  });

  it("processes an enqueued heartbeat job", async () => {
    const before = service.heartbeats;
    const id = await service.enqueueHeartbeat();
    expect(id).toBeTruthy();
    await expect.poll(() => service.heartbeats, { timeout: 20_000 }).toBeGreaterThan(before);
  });
});
