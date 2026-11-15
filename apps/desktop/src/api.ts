// The only module that talks to the Rust side. No command carries a secret value:
// the *Secure commands open a native prompt in Rust.
import { invoke } from "@tauri-apps/api/core";
import type {
  AuditEvent, AuditVerifyView, HttpTokenInfo, RelayInfo, SecureOutcome, StatusView,
} from "@locksmith/api-types";

// Dev server in a plain browser only: `import.meta.env.DEV` is false in `vite build`, so the
// mock branch and its dynamic import are removed from the shipped bundle.
const useMock = import.meta.env.DEV && !("__TAURI_INTERNALS__" in window);
const call = <T>(cmd: string, args?: Record<string, unknown>): Promise<T> =>
  useMock ? import("./mock").then((m) => m.invoke<T>(cmd, args)) : invoke<T>(cmd, args);

export const status = () => call<StatusView>("status");
export const lock = () => call<null>("lock");
export const unlockSecure = () => call<SecureOutcome>("unlock_secure");
export const revoke = (id: string | null) => call<number>("revoke", { id });
export const auditList = (limit: number) => call<AuditEvent[]>("audit_list", { limit });
export const auditVerify = () => call<AuditVerifyView>("audit_verify");
export const keyNames = (project: string, env: string) =>
  call<string[]>("key_names", { project, env });
export const putSecretSecure = (project: string, env: string, name: string) =>
  call<SecureOutcome>("put_secret_secure", { project, env, name });
export const tokenList = () => call<HttpTokenInfo[]>("token_list");
export const tokenRevoke = (token: string) => call<number>("token_revoke", { token });
export const relayInfo = () => call<RelayInfo>("relay_info");
