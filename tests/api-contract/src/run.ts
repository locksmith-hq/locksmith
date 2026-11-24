// CLI: `node src/run.ts <base-url> <out.json>` runs every scenario and writes the transcript;
// `node src/run.ts --diff <a.json> <b.json>` prints the first difference per exchange.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { Recorder, type Exchange } from "./client.ts";
import { diffTranscripts } from "./diff.ts";
import { Ctx, loadScenarios } from "./scenario.ts";
import { seed } from "./seed.ts";

async function record(url: string, out: string): Promise<void> {
  process.env.API_CONTRACT_URL = url;
  const rec = new Recorder();
  const s = await seed();
  rec.norm.literal(s.run, "<run>");
  for (const sc of await loadScenarios()) await sc.run(new Ctx(rec, s, sc.id));
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, `${JSON.stringify(rec.exchanges, null, 2)}\n`);
  console.log(`api-contract: ${rec.exchanges.length} exchanges -> ${out}`);
}

async function diff(a: string, b: string): Promise<number> {
  const load = async (p: string) => JSON.parse(await readFile(p, "utf8")) as Exchange[];
  const d = diffTranscripts(await load(a), await load(b));
  for (const x of d) console.log(`DIFF ${x.where}: ${x.field}: ${JSON.stringify(x.a)} != ${JSON.stringify(x.b)}`);
  console.log(d.length === 0 ? "api-contract: transcripts match" : `api-contract: ${d.length} difference(s)`);
  return d.length === 0 ? 0 : 1;
}

const args = process.argv.slice(2);
if (args[0] === "--diff" && args.length === 3) {
  process.exitCode = await diff(args[1] as string, args[2] as string);
} else if (args.length === 2 && !args[0]?.startsWith("--")) {
  await record(args[0] as string, args[1] as string);
} else {
  console.error("usage: run.ts <base-url> <out.json> | run.ts --diff <a.json> <b.json>");
  process.exitCode = 2;
}
