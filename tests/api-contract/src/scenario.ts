import { Recorder, type Call } from "./client.ts";
import type { Json } from "./normalise.ts";
import type { Seed } from "./seed.ts";

/** What a scenario file hands the runner: one entry per behaviour on the API. */
export interface Scenario {
  /** Unique, stable name; it is the transcript key prefix. */
  id: string;
  /** `METHOD /path/{template}` entries from openapi.json this scenario exercises. */
  covers: string[];
  run(ctx: Ctx): Promise<void>;
}

export class Ctx {
  readonly rec: Recorder;
  readonly seed: Seed;
  private readonly scenario: string;

  constructor(rec: Recorder, seed: Seed, scenario: string) {
    this.rec = rec;
    this.seed = seed;
    this.scenario = scenario;
  }

  /** Sends a call, records it, and fails the run when the status is not the expected one. */
  async expect(label: string, status: number, call: Call): Promise<{ status: number; body: Json | null }> {
    const name = `${this.scenario}: ${label}`;
    const res = await this.rec.call(name, call);
    if (res.status !== status) {
      throw new Error(`${name}: expected ${status}, got ${res.status} ${JSON.stringify(res.body)}`);
    }
    return res;
  }
}

/** Scenario ids named by a comma list (`API_CONTRACT_SCENARIOS`); empty or unset means all. */
export function parseScenarioFilter(raw: string | undefined): string[] {
  return (raw ?? "").split(",").map((x) => x.trim()).filter((x) => x !== "");
}

/** Every scenario in `src/scenarios`, in file order, or only those whose `id` is in `only`; the coverage test reads `covers`. */
export async function loadScenarios(only: string[] = parseScenarioFilter(process.env.API_CONTRACT_SCENARIOS)): Promise<Scenario[]> {
  const { readdir } = await import("node:fs/promises");
  const dir = new URL("./scenarios/", import.meta.url);
  const files = (await readdir(dir)).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts")).sort();
  const all: Scenario[] = [];
  for (const f of files) {
    const mod = (await import(new URL(f, dir).href)) as { scenarios: Scenario[] };
    all.push(...mod.scenarios);
  }
  const unknown = only.filter((o) => !all.some((sc) => sc.id === o));
  if (unknown.length > 0) throw new Error(`unknown scenario id(s): ${unknown.join(", ")}`);
  return only.length === 0 ? all : all.filter((sc) => only.includes(sc.id));
}
