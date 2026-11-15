import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { App } from "./App";
import * as api from "./api";

vi.mock("./api");
const m = vi.mocked(api);

const lease = {
  id: "L1", root_pid: 1, command: "claude", project: "default", env: "development",
  scopes: ["git", "http"], created_at: 0, expires_at: Math.floor(Date.now() / 1000) + 600, state: "active",
};
const ev = (seq: number, action: string) => ({
  seq, ts: 1700000000, session_id: "L1", actor_pid: 2, actor_exe: "/bin/git",
  action, target: "github.com", policy_rule: "r1", decision: "allow",
});

beforeEach(() => {
  vi.resetAllMocks();
  m.status.mockResolvedValue({ locked: false, leases: [lease] });
  m.lock.mockResolvedValue(null);
  m.unlockSecure.mockResolvedValue("submitted");
  m.revoke.mockResolvedValue(1);
  m.keyNames.mockResolvedValue(["GITHUB_TOKEN"]);
  m.putSecretSecure.mockResolvedValue("submitted");
  m.tokenList.mockResolvedValue([{
    prefix: "lsk_ab12", key: "k", project: "default", env: "development",
    hosts: ["api.example.com"], placement: "header", lease: "L1", created_at: 1700000000,
  }]);
  m.tokenRevoke.mockResolvedValue(1);
  m.relayInfo.mockResolvedValue({ git_port: 9418, http_port: null, aws_port: 4566, ca_hosts: ["github.com"] });
  m.auditList.mockResolvedValue([ev(1, "git.fetch"), ev(2, "http.request")]);
  m.auditVerify.mockResolvedValue({ events: 2, broken_at: null, detail: "chain intact" });
});

const noPassword = (c: HTMLElement) => expect(c.querySelector("input[type=password]")).toBeNull();
const go = (name: string) => userEvent.click(screen.getByRole("button", { name }));

test("overview lists sessions, revoke and revoke all", async () => {
  const { container } = render(<App />);
  expect(await screen.findByText("claude")).toBeInTheDocument();
  expect(screen.getByText("Unlocked")).toBeInTheDocument();
  await go("Revoke L1");
  // The row is struck through first, then the revoke goes out.
  await waitFor(() => expect(m.revoke).toHaveBeenCalledWith("L1"));
  await go("Revoke all sessions");
  expect(m.revoke).toHaveBeenCalledWith(null);
  await go("Lock now");
  expect(m.lock).toHaveBeenCalled();
  noPassword(container);
});

test("unlock calls unlock_secure and shows result, no password input anywhere", async () => {
  m.status.mockResolvedValue({ locked: true, leases: [] });
  m.unlockSecure.mockResolvedValue("cancelled");
  const { container } = render(<App />);
  expect(await screen.findByText("Locked")).toBeInTheDocument();
  await go("Unlock");
  expect(m.unlockSecure).toHaveBeenCalled();
  expect(await screen.findByText(/Unlock cancelled/)).toBeInTheDocument();
  for (const t of ["Overview", "Keys", "Tokens", "Relays", "Audit"]) {
    await go(t);
    noPassword(container);
  }
});

test("keys: defaults to the live session's project and names the sessions that can use the keys", async () => {
  m.status.mockResolvedValue({ locked: false, leases: [{ ...lease, project: "acme", env: "staging", scopes: ["run"] }] });
  render(<App />);
  await screen.findByText("claude");
  await go("Keys");
  await waitFor(() => expect(m.keyNames).toHaveBeenCalledWith("acme", "staging"));
  expect(await screen.findByText(/Usable now by/)).toHaveTextContent("L1 (claude)");
  expect(screen.queryByRole("columnheader", { name: "Project / env" })).toBeNull();
});

test("keys: lists names and add or rotate calls put_secret_secure", async () => {
  render(<App />);
  await go("Keys");
  expect(await screen.findByText("GITHUB_TOKEN")).toBeInTheDocument();
  expect(m.keyNames).toHaveBeenCalledWith("default", "development");
  await userEvent.type(screen.getByLabelText("Key name"), "NPM_TOKEN");
  await go("Add or rotate key");
  expect(m.putSecretSecure).toHaveBeenCalledWith("default", "development", "NPM_TOKEN");
  expect(await screen.findByText(/Key NPM_TOKEN saved/)).toBeInTheDocument();
});

test("tokens: list and revoke", async () => {
  render(<App />);
  await go("Tokens");
  expect(await screen.findByText("lsk_ab12")).toBeInTheDocument();
  await go("Revoke token lsk_ab12");
  expect(m.tokenRevoke).toHaveBeenCalledWith("lsk_ab12");
});

test("relays: ports, instructions and CA hosts", async () => {
  render(<App />);
  await go("Relays");
  const git = (await screen.findByRole("rowheader", { name: "Git forwarder" })).closest("tr")!;
  expect(git).toHaveTextContent("9418");
  expect(screen.getByRole("rowheader", { name: "HTTP relay" }).closest("tr")).toHaveTextContent("not running");
  expect(screen.getByText("smith git setup")).toBeInTheDocument();
  expect(screen.getByText("smith token issue <KEY> --provider <name>")).toBeInTheDocument();
  expect(screen.getByText("github.com")).toBeInTheDocument();
});

test("audit: rows, filter, verify OK", async () => {
  render(<App />);
  await go("Audit");
  expect(await screen.findByText("git.fetch")).toBeInTheDocument();
  expect(m.auditList).toHaveBeenCalledWith(200);
  await userEvent.type(screen.getByLabelText("Filter"), "http.request");
  expect(screen.queryByText("git.fetch")).toBeNull();
  await go("Verify ledger");
  expect(await screen.findByText("Ledger intact: 2 events checked, hash chain unbroken.")).toBeInTheDocument();
  expect(screen.queryByText(/chain intact/)).toBeNull();
});

test("audit: BROKEN shows seq", async () => {
  m.auditVerify.mockResolvedValue({ events: 2, broken_at: 7, detail: "hash mismatch" });
  render(<App />);
  await go("Audit");
  await go("Verify ledger");
  expect(await screen.findByText(/BROKEN at seq 7/)).toBeInTheDocument();
});

test("errors show the message", async () => {
  m.revoke.mockRejectedValue({ code: "Locked", message: "vault is locked" });
  render(<App />);
  await screen.findByText("claude");
  await go("Revoke L1");
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("vault is locked"));
});

test("key cut names granted scopes for assistive tech", async () => {
  render(<App />);
  expect(await screen.findByRole("img", { name: "Scopes granted: git, http" })).toBeInTheDocument();
});

test("struck sessions appear only when the daemon returns them", async () => {
  render(<App />);
  await screen.findByText("claude");
  expect(screen.queryByText("Struck from the schedule")).toBeNull();
  m.status.mockResolvedValue({ locked: false, leases: [lease, { ...lease, id: "L0", state: "revoked" }, { ...lease, id: "L9", state: "revoked" }] });
  m.auditList.mockResolvedValue([{ ...ev(3, "REVOKE"), target: "L0" }]);
  await go("Revoke L1");
  expect(await screen.findByText("Struck from the schedule")).toBeInTheDocument();
  const t = new Date(1700000000 * 1000);
  const hhmm = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`;
  expect(screen.getByText("L0", { selector: "s" }).closest("tr")).toHaveTextContent(`revoked ${hhmm}`);
  // No REVOKE event for L9 in the loaded ledger: plain "revoked".
  expect(screen.getByText("L9", { selector: "s" }).closest("tr")!.lastElementChild).toHaveTextContent(/^revoked$/);
});

test("ledger targets break only after / and :", async () => {
  m.auditList.mockResolvedValue([{ ...ev(1, "ACCESS"), target: "acme/dev/KEY http:api.x.com" }]);
  const { container } = render(<App />);
  await screen.findByText("ACCESS");
  expect(container.querySelector(".ev-target")!.innerHTML).toBe("acme/<wbr>dev/<wbr>KEY http:<wbr>api.x.com");
});

test("empty schedule tells how to start a session", async () => {
  m.status.mockResolvedValue({ locked: false, leases: [] });
  render(<App />);
  expect(await screen.findByText(/No keys cut right now/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Revoke all sessions" })).toBeDisabled();
});

test("daemon unavailable shows the start command", async () => {
  m.status.mockRejectedValue({ code: "Unavailable", message: "locksmithd: connection refused" });
  const { container } = render(<App />);
  expect(await screen.findByRole("heading", { name: /daemon is not running/ })).toBeInTheDocument();
  expect(screen.getByText("locksmithd", { selector: "pre code" })).toBeInTheDocument();
  noPassword(container);
});
