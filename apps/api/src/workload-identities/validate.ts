import { isIP } from "node:net";

/**
 * Create-time validation of a workload identity trust policy. A faithful port of the pure functions
 * in Rust `crates/ls-oidc-verify/src/workload.rs` (`validate`, `IssuerKind`, `Condition`, `Op`,
 * `encode_handle`). Nothing here holds a secret.
 */

const HANDLE_PREFIX = "lsw_";
/** The only issuer a `github` policy can name. */
export const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
const MAX_CONDITIONS = 16;
const MAX_VALUE_LEN = 512;
const MAX_CLAIM_LEN = 64;

export type IssuerKind = "github" | "oidc";
type Op = "eq" | "prefix";

/** One claim test as stored. Conditions are ANDed. */
export interface Condition {
  claim: string;
  op: Op;
  value: string;
}

/** A condition as sent by the caller: `value` may end in one `*`. */
export interface ConditionInput {
  claim: string;
  value: string;
}

export interface ValidatedPolicy {
  issuer_kind: IssuerKind;
  issuer: string;
  audience: string;
  conditions: Condition[];
}

/** Rust `PolicyError::detail`: static text, safe to return to the caller. */
const DETAIL = {
  Name: "name must not be empty",
  IssuerNotHttps: "issuer must be an https URL without credentials, query or fragment",
  IssuerNotAllowed: "a github policy can only use the GitHub Actions issuer",
  Audience: "audience is required",
  NoConditions: "at least one condition is required",
  TooManyConditions: "too many conditions",
  BadCondition: "a condition needs a claim name and a value (a trailing * is the only wildcard)",
  BareWildcard: "a bare * is not allowed; pin the claim to a value",
  NoSubjectPin: "a condition must pin the subject (repository or sub)",
} as const;

export type PolicyErrorCode = keyof typeof DETAIL;

/** Why a policy was refused (the API maps it to a 422 with `detail`). */
export class PolicyError extends Error {
  readonly detail: string;
  constructor(readonly code: PolicyErrorCode) {
    super(code);
    this.detail = DETAIL[code];
  }
}

/** Rust `IssuerKind::parse`. */
export function parseIssuerKind(s: string): IssuerKind | null {
  return s === "github" || s === "oidc" ? s : null;
}

/** The claims that must be pinned by an `eq` or `prefix` condition. */
const subjectClaims = (kind: IssuerKind): string[] => (kind === "github" ? ["repository", "sub"] : ["sub"]);

const trimEndSlashes = (s: string) => s.replace(/\/+$/, "");

/**
 * Rust `validate`. `issuer` is ignored (fixed) for `github`, unless it names another issuer.
 * Check order is the Rust order, so the first refusal is the same.
 */
export function validate(
  name: string,
  kind: IssuerKind,
  issuer: string | null | undefined,
  audience: string,
  inputs: ConditionInput[],
): ValidatedPolicy {
  if (name.trim() === "") throw new PolicyError("Name");
  let resolved: string;
  if (kind === "github") {
    if (issuer == null || trimEndSlashes(issuer) === GITHUB_ISSUER) resolved = GITHUB_ISSUER;
    else throw new PolicyError("IssuerNotAllowed");
  } else {
    resolved = normaliseIssuer(issuer ?? "");
  }
  if (audience.trim() === "") throw new PolicyError("Audience");
  if (inputs.length === 0) throw new PolicyError("NoConditions");
  if (inputs.length > MAX_CONDITIONS) throw new PolicyError("TooManyConditions");
  // The GitHub issuer is shared by all of github.com, whichever kind names it.
  const shared = kind === "github" || resolved === GITHUB_ISSUER;
  const conditions = inputs.map(parseCondition);
  const pinned = conditions.some((c) => subjectClaims(kind).includes(c.claim) && pinsSubject(shared, c));
  if (!pinned) throw new PolicyError("NoSubjectPin");
  return { issuer_kind: kind, issuer: resolved, audience: audience.trim(), conditions };
}

/**
 * A subject pin must narrow the caller to one owner. An exact value always does. A prefix on a shared issuer
 * (GitHub) must fix the owner: `repo:*`, `a*` or `acme*` would let any outside workflow match, so the owner
 * segment must be closed by a `/`.
 */
function pinsSubject(sharedIssuer: boolean, c: Condition): boolean {
  if (c.op === "eq" || !sharedIssuer) return true;
  let ownerAndRest = c.value;
  if (c.claim === "sub") {
    if (!c.value.startsWith("repo:")) return false;
    ownerAndRest = c.value.slice("repo:".length);
  }
  const slash = ownerAndRest.indexOf("/");
  return slash > 0;
}

function normaliseIssuer(raw: string): string {
  if (!raw.startsWith("https://")) throw new PolicyError("IssuerNotHttps");
  const rest = raw.slice("https://".length);
  const hostPart = rest.split("/")[0] ?? "";
  if (hostPart === "" || hostPart.includes("@") || raw.includes("?") || raw.includes("#") || /[\s\p{Cc}]/u.test(raw))
    throw new PolicyError("IssuerNotHttps");
  return trimEndSlashes(raw);
}

function parseCondition(i: ConditionInput): Condition {
  const claim = i.claim.trim();
  const value = i.value;
  // Rust `len()` is bytes.
  if (
    claim === "" ||
    value === "" ||
    Buffer.byteLength(value) > MAX_VALUE_LEN ||
    Buffer.byteLength(claim) > MAX_CLAIM_LEN
  )
    throw new PolicyError("BadCondition");
  if (value === "*") throw new PolicyError("BareWildcard");
  const stars = value.split("*").length - 1;
  if (value.endsWith("*") && stars === 1) return { claim, op: "prefix", value: value.slice(0, -1) };
  if (stars === 0) return { claim, op: "eq", value };
  throw new PolicyError("BadCondition");
}

/** A condition as shown to callers: a prefix ends in `*` (Rust `view`). */
export const toPattern = (c: Condition): string => (c.op === "prefix" ? `${c.value}*` : c.value);

/** Rust `encode_handle`: `lsw_` + base64url (no padding) of `org_id(16) || policy_id(16)`. */
export function encodeHandle(orgId: string, policyId: string): string {
  const raw = Buffer.from(orgId.replaceAll("-", "") + policyId.replaceAll("-", ""), "hex");
  return `${HANDLE_PREFIX}${raw.toString("base64url")}`;
}

/** Rust `parse_handle`: the org and policy ids of a well-formed `lsw_` handle, else null. */
export function decodeHandle(text: string): { orgId: string; policyId: string } | null {
  const t = text.trim();
  if (!t.startsWith(HANDLE_PREFIX)) return null;
  const body = t.slice(HANDLE_PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(body)) return null;
  const raw = Buffer.from(body, "base64url");
  if (raw.length !== 32) return null;
  const uuid = (b: Buffer) => {
    const h = b.toString("hex");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  };
  return { orgId: uuid(raw.subarray(0, 16)), policyId: uuid(raw.subarray(16)) };
}

/**
 * Create-time issuer address check (Rust `check_issuer_host`, minus DNS). Makes no network call, so it refuses
 * only what the URL itself shows: a literal private, loopback, link-local, metadata or unspecified IP, `localhost`
 * and `*.localhost`, and the cloud metadata hostname. A name that resolves to a private address is NOT caught here
 * (Rust resolves the name); the exchange route still refuses it when it fetches the issuer keys.
 * `allowPrivate` is Rust's `LOCKSMITH_WORKLOAD_ALLOW_PRIVATE_ISSUERS` (local development only): metadata stays refused.
 */
export function issuerHostAllowed(issuer: string, allowPrivate = false): boolean {
  let host: string;
  try {
    host = new URL(issuer).hostname;
  } catch {
    return false;
  }
  host = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "") return false;
  if (host === "metadata.google.internal") return false;
  const kind = isIP(host);
  if (kind !== 0) return ipAllowed(host, kind === 6, allowPrivate);
  if (host === "localhost" || host.endsWith(".localhost")) return allowPrivate;
  return true;
}

/** Rust `address_allowed`: metadata, multicast and unspecified never; private only when allowed. */
function ipAllowed(ip: string, v6: boolean, allowPrivate: boolean): boolean {
  const octets = v6 ? mappedV4(ip) : v4Octets(ip);
  if (octets) {
    const [a, b, c, d] = octets as [number, number, number, number];
    if (a === 169 && b === 254 && c === 169 && d === 254) return false; // metadata
    if (a >= 224 && a <= 239) return false; // multicast
    if (a === 0 && b === 0 && c === 0 && d === 0) return false; // unspecified
    const priv =
      a === 127 ||
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 255 && b === 255 && c === 255 && d === 255) ||
      a === 0 ||
      (a === 100 && (b & 0xc0) === 64);
    return allowPrivate || !priv;
  }
  const words = v6Words(ip);
  if (!words) return false;
  const first = words[0]!;
  if (words.join(":") === [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254].join(":")) return false; // metadata
  if ((first & 0xff00) === 0xff00) return false; // multicast
  if (words.every((w) => w === 0)) return false; // unspecified
  const priv =
    (words.slice(0, 7).every((w) => w === 0) && words[7] === 1) || // loopback
    (first & 0xfe00) === 0xfc00 || // unique local
    (first & 0xffc0) === 0xfe80; // link-local
  return allowPrivate || !priv;
}

const v4Octets = (ip: string): number[] => ip.split(".").map(Number);

/** The IPv4 octets of an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`), judged as the IPv4 address it carries. */
function mappedV4(ip: string): number[] | null {
  const w = v6Words(ip);
  if (!w || !w.slice(0, 5).every((x) => x === 0) || w[5] !== 0xffff) return null;
  return [w[6]! >> 8, w[6]! & 0xff, w[7]! >> 8, w[7]! & 0xff];
}

/** Expand an IPv6 literal to eight 16-bit words (handles `::` and a dotted IPv4 tail). */
function v6Words(ip: string): number[] | null {
  let s = ip.split("%")[0]!;
  const dotted = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const o = v4Octets(dotted[2]!);
    s = `${dotted[1]}${((o[0]! << 8) | o[1]!).toString(16)}:${((o[2]! << 8) | o[3]!).toString(16)}`;
  }
  const [head = "", tail, extra] = s.split("::");
  if (extra !== undefined) return null;
  const h = head === "" ? [] : head.split(":");
  const t = tail === undefined || tail === "" ? [] : tail.split(":");
  const fill = tail === undefined ? 0 : 8 - h.length - t.length;
  if (fill < 0 || (tail === undefined && h.length !== 8)) return null;
  const words = [...h, ...Array<string>(fill).fill("0"), ...t].map((x) => parseInt(x, 16));
  return words.length === 8 && words.every((w) => Number.isInteger(w)) ? words : null;
}
