import { Inject, Injectable } from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { ProblemException } from "../platform/problem.js";
import { TenantService, type Tx } from "../tenant/tenant.service.js";
import { MAX_NAME_CHARS, type Org } from "./orgs.schemas.js";

const COLS = ["id", "name", "region", "created_at", "updated_at"] as const;

type Row = { id: string; name: string; region: string; created_at: Date; updated_at: Date };
const toOrg = (r: Row): Org => ({
  id: r.id,
  name: r.name,
  region: r.region,
  created_at: new Date(r.created_at).toISOString(),
  updated_at: new Date(r.updated_at).toISOString(),
});

/** Rust `validate_name`: not blank, at most 200 characters. */
export function validateName(name: string): void {
  if (name.trim() === "") throw new ProblemException("validation", "`name` must not be empty");
  if ([...name].length > MAX_NAME_CHARS)
    throw new ProblemException("validation", `\`name\` must be at most ${MAX_NAME_CHARS} characters`);
}

/** UUIDv7 (RFC 9562): 48-bit millisecond timestamp, then random bits. */
export function uuidv7(now = Date.now()): string {
  const b = Buffer.from(randomUUID().replaceAll("-", ""), "hex");
  b.writeUIntBE(now, 0, 6);
  b[6] = (b[6]! & 0x0f) | 0x70;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

@Injectable()
export class OrgsService {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  /** Dev-only create: the id is bound as the org context, and the insert runs through row-level security. */
  async create(name: string): Promise<Org> {
    validateName(name);
    const id = uuidv7();
    return this.tenant.run(id, async (tx) => {
      const row = await tx.insertInto("orgs").values({ id, name }).returning(COLS).executeTakeFirstOrThrow();
      return toOrg(row);
    });
  }

  /** The bound org, read in the request's tenant transaction. */
  async bound(orgId: string, tx: Tx = this.tenant.tx()): Promise<Org> {
    const row = await tx.selectFrom("orgs").select(COLS).where("id", "=", orgId).executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toOrg(row);
  }
}
