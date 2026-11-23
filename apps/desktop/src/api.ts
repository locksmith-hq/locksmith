// The only module that talks to the Rust side. No command carries a secret value:
// the *Secure commands open a native prompt in Rust.
import { invoke } from "@tauri-apps/api/core";
import { createClient, type Client as AgentsClientT } from "@locksmith/control-plane-client";
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

// Agents and grants live in the control plane, not the daemon: the frontend calls its REST API
// directly (tauri.conf.json allows only loopback in connect-src; the control plane answers the
// CORS preflight for Tauri origins only). The URL and org id are not
// secrets; the enrollment secret is returned to the screen and never stored.
export { type WorkloadIdentity, type WorkloadPreset } from "@locksmith/control-plane-client";
export { type Agent, type AgentGrant, type AuditEvent as OrgAuditEvent, type AuditStatus, type Client as AgentsClient, type BindingSummary, type McpClient, type McpToolSetting } from "@locksmith/control-plane-client";
const CP_URL = "locksmith.controlPlane";
const CP_ORG = "locksmith.org";
const store = {
  get: (k: string, d = "") => { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set: (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* keep for this window only */ } },
};
export const controlPlane = {
  url: () => store.get(CP_URL, "http://127.0.0.1:8080"),
  org: () => store.get(CP_ORG),
  save: (url: string, org: string) => { store.set(CP_URL, url); store.set(CP_ORG, org); },
};
export const agentsClient = (): AgentsClientT | null => {
  const org = controlPlane.org();
  return org ? createClient(org, controlPlane.url()) : null;
};
