import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { App } from "./App";
import * as api from "./api";

vi.mock("./api");
const m = vi.mocked(api);

const lease = {
  id: "L1", root_pid: 1, command: "claude", project: "default", env: "development",
  scopes: ["git", "http"], created_at: 0, expires_at: Math.floor(Date.now() / 1000) + 600, state: "active",
  root_exe: "/bin/claude", started_by: "human" as const, source: { kind: "claude_code_cli" as const, label: "Claude Code" }, host: null, report: null,
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
  localStorage.clear();
  delete document.documentElement.dataset.theme;
});

const noPassword = (c: HTMLElement) => expect(c.querySelector("input[type=password]")).toBeNull();
const go = (name: string) => userEvent.click(screen.getByRole("button", { name }));
/** Sidebar items carry a count after the label, e.g. "Tokens 1". */
const nav = (tab: string) =>
  userEvent.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("button", { name: new RegExp(`^${tab}\\b`) }));

test("overview lists sessions, revoke and revoke all", async () => {
  const { container } = render(<App />);
  expect(await screen.findByText("claude", { selector: ".who-name" })).toBeInTheDocument();
  expect(screen.getByRole("banner", { name: "Vault" })).toHaveTextContent("Unlocked1 session");
  await go("Revoke claude session L1");
  // The card is struck through first, then the revoke goes out.
  await waitFor(() => expect(m.revoke).toHaveBeenCalledWith("L1"));
  await go("Revoke all sessions");
  expect(m.revoke).toHaveBeenCalledWith(null);
  await go("Lock vault");
  expect(m.lock).toHaveBeenCalled();
  noPassword(container);
});

test("unlock calls unlock_secure and shows result, no password input anywhere", async () => {
  m.status.mockResolvedValue({ locked: true, leases: [] });
  m.unlockSecure.mockResolvedValue("cancelled");
  const { container } = render(<App />);
  expect(await screen.findByText("Locked")).toBeInTheDocument();
  await go("Unlock vault");
  expect(m.unlockSecure).toHaveBeenCalled();
  expect(await screen.findByText(/Unlock cancelled/)).toBeInTheDocument();
  for (const t of ["Overview", "Sessions", "Keys", "Tokens", "Relays", "Audit"]) {
    await nav(t);
    noPassword(container);
  }
});

test("keys: defaults to the live session's project and names the sessions that can use the keys", async () => {
  m.status.mockResolvedValue({ locked: false, leases: [{ ...lease, project: "acme", env: "staging", scopes: ["run"] }] });
  render(<App />);
  await screen.findByText("claude", { selector: ".who-name" });
  await nav("Keys");
  await waitFor(() => expect(m.keyNames).toHaveBeenCalledWith("acme", "staging"));
  expect(await screen.findByText(/Usable now by/)).toHaveTextContent("L1 (claude)");
});

test("keys: lists names and add or rotate calls put_secret_secure", async () => {
  render(<App />);
  await nav("Keys");
  expect(await screen.findByText("GITHUB_TOKEN")).toBeInTheDocument();
  expect(m.keyNames).toHaveBeenCalledWith("default", "development");
  await userEvent.type(screen.getByLabelText("Key name"), "NPM_TOKEN");
  await go("Add or rotate key");
  expect(m.putSecretSecure).toHaveBeenCalledWith("default", "development", "NPM_TOKEN");
  expect(await screen.findByText(/Key NPM_TOKEN saved/)).toBeInTheDocument();
});

test("tokens: list and revoke", async () => {
  render(<App />);
  await nav("Tokens");
  expect(await screen.findByText("lsk_ab12")).toBeInTheDocument();
  await go("Revoke token lsk_ab12");
  expect(m.tokenRevoke).toHaveBeenCalledWith("lsk_ab12");
});

test("relays: ports, instructions and CA hosts", async () => {
  render(<App />);
  await nav("Relays");
  expect(await screen.findByRole("article", { name: "Git forwarder" })).toHaveTextContent("Port 9418");
  expect(screen.getByRole("article", { name: "HTTP relay" })).toHaveTextContent("Not running");
  expect(screen.getByRole("article", { name: "Database relay" })).toHaveTextContent("Per target");
  expect(screen.getByText("smith git setup")).toBeInTheDocument();
  expect(screen.getByText("smith token issue <KEY> --provider <name>")).toBeInTheDocument();
  expect(screen.getByText("github.com")).toBeInTheDocument();
});

test("audit: rows, filter, verify OK", async () => {
  render(<App />);
  await nav("Audit");
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
  await nav("Audit");
  await go("Verify ledger");
  expect(await screen.findByText(/BROKEN at seq 7/)).toBeInTheDocument();
});

test("errors show the message", async () => {
  m.revoke.mockRejectedValue({ code: "Locked", message: "vault is locked" });
  render(<App />);
  await screen.findByText("claude", { selector: ".who-name" });
  await go("Revoke claude session L1");
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("vault is locked"));
});

test("scope chips name granted scopes for assistive tech", async () => {
  render(<App />);
  expect(await screen.findByRole("list", { name: "Scopes granted: git, http" })).toBeInTheDocument();
});

test("the agent is the basename of the command's first word", async () => {
  m.status.mockResolvedValue({ locked: false, leases: [{ ...lease, command: "/opt/homebrew/bin/codex exec --full-auto" }] });
  render(<App />);
  expect(await screen.findByRole("listitem", { name: "codex session L1" })).toBeInTheDocument();
});

test("ended sessions appear only when the daemon returns them", async () => {
  render(<App />);
  await screen.findByText("claude", { selector: ".who-name" });
  expect(screen.queryByText("Recently ended")).toBeNull();
  m.status.mockResolvedValue({ locked: false, leases: [lease, { ...lease, id: "L0", state: "revoked" }, { ...lease, id: "L9", state: "revoked" }] });
  m.auditList.mockResolvedValue([{ ...ev(3, "REVOKE"), target: "L0" }]);
  await go("Revoke claude session L1");
  expect(await screen.findByText("Recently ended")).toBeInTheDocument();
  const t = new Date(1700000000 * 1000);
  const hhmm = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`;
  expect(screen.getByRole("listitem", { name: `claude session L0, revoked ${hhmm}` })).toHaveTextContent(`revoked ${hhmm}`);
  // No REVOKE event for L9 in the loaded ledger: plain "revoked".
  expect(screen.getByRole("listitem", { name: "claude session L9, revoked" }).querySelector(".end")).toHaveTextContent(/^revoked$/);
});

test("activity reads as a log: sentence-case labels, blocked rows marked, full target in a tooltip", async () => {
  m.auditList.mockResolvedValue([
    { ...ev(1, "ACCESS"), target: "acme/dev/KEY http:api.x.com" },
    { ...ev(2, "HOOK_DENY"), decision: "DENY", target: "Bash: cat ~/.ssh/id_rsa" },
    { ...ev(3, "REVOKE"), target: "L0" },
    { ...ev(4, "SOME_NEW_THING") },
  ]);
  render(<App />);
  const used = (await screen.findByText("Key used")).closest("li")!;
  expect(used).toHaveAttribute("data-kind", "allowed");
  expect(used.querySelector(".tgt")).toHaveAttribute("title", "acme/dev/KEY http:api.x.com");
  expect(used).toHaveTextContent("claude L1");
  expect(screen.getByText("Blocked hook").closest("li")).toHaveAttribute("data-kind", "blocked");
  expect(screen.getByText("Revoked").closest("li")).toHaveAttribute("data-kind", "revoked");
  expect(screen.getByText("Some new thing")).toBeInTheDocument();
});

test("empty schedule tells how to start a session", async () => {
  m.status.mockResolvedValue({ locked: false, leases: [] });
  render(<App />);
  expect(await screen.findByText(/No active sessions/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Revoke all sessions" })).toBeDisabled();
});

test("daemon unavailable shows the start command", async () => {
  m.status.mockRejectedValue({ code: "Unavailable", message: "locksmithd: connection refused" });
  const { container } = render(<App />);
  expect(await screen.findByRole("heading", { name: /daemon is not running/ })).toBeInTheDocument();
  expect(screen.getByText("locksmithd", { selector: "pre code" })).toBeInTheDocument();
  noPassword(container);
});

test("overview footer shows the verified ledger count, and BROKEN when the chain fails", async () => {
  m.auditVerify.mockResolvedValue({ events: 1284, broken_at: null, detail: "" });
  render(<App />);
  expect(await screen.findByText("Ledger chain verified · 1,284 entries")).toBeInTheDocument();
});

test("vault header states the vault, offers one primary action and turns the sidebar dial", async () => {
  const { container } = render(<App />);
  const vault = await screen.findByRole("banner", { name: "Vault" });
  await waitFor(() => expect(vault).toHaveTextContent("Unlocked"));
  const dial = () => container.querySelector(".logo .vault-mark")!;
  expect(dial()).toHaveAttribute("data-open", "true");
  expect(screen.queryByRole("switch")).toBeNull();
  await go("Lock vault");
  expect(m.lock).toHaveBeenCalled();
  m.status.mockResolvedValue({ locked: true, leases: [] });
  await go("Revoke all sessions");
  await waitFor(() => expect(vault).toHaveTextContent("LockedAgents cannot start sessions or use keys"));
  expect(dial()).toHaveAttribute("data-open", "false");
  expect(screen.getByRole("button", { name: "Revoke all sessions" })).toBeDisabled();
  await go("Unlock vault");
  expect(m.unlockSecure).toHaveBeenCalled();
});

test("vault header shows since when, from the ledger's last UNLOCK", async () => {
  m.auditList.mockResolvedValue([{ ...ev(1, "UNLOCK"), ts: 1700000000 }]);
  render(<App />);
  const t = new Date(1700000000 * 1000);
  const hhmm = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`;
  await waitFor(() => expect(screen.getByRole("banner", { name: "Vault" })).toHaveTextContent(`since ${hhmm}`));
});

test("appearance override sets the theme and is remembered", async () => {
  render(<App />);
  expect(screen.getByRole("radio", { name: "System" })).toBeChecked();
  await userEvent.click(screen.getByRole("radio", { name: "Dark" }));
  expect(document.documentElement.dataset.theme).toBe("dark");
  expect(localStorage.getItem("locksmith.appearance")).toBe("dark");
  await userEvent.click(screen.getByRole("radio", { name: "Light" }));
  expect(document.documentElement.dataset.theme).toBe("light");
  await userEvent.click(screen.getByRole("radio", { name: "System" }));
  expect(localStorage.getItem("locksmith.appearance")).toBeNull();
});

test("sessions: tab count, source, host, badges, reported model, unknown source, revoke", async () => {
  const soon = Math.floor(Date.now() / 1000) + 3000;
  m.status.mockResolvedValue({ locked: false, leases: [
    { ...lease, id: "A1", expires_at: soon, started_by: "agent", host: "iTerm2", report: { agent: "claude-code", model: "claude-fable-5-2", reported: true } },
    { ...lease, id: "A2", expires_at: soon, started_by: "agent", report: null },
    { ...lease, id: "H1", expires_at: soon, source: { kind: "unknown", label: "mystery-agent" } },
    { ...lease, id: "E1", state: "revoked", expires_at: soon },
  ] });
  render(<App />);
  expect(await within(screen.getByRole("navigation", { name: "Main" })).findByRole("button", { name: "Sessions 3" })).toBeInTheDocument();
  await nav("Sessions");
  const a1 = (await screen.findByRole("button", { name: "Claude Code session A1" })).closest("li")!;
  expect(a1).toHaveTextContent("in iTerm2");
  expect(a1).toHaveTextContent("Agent started");
  const rep = within(a1).getByText("claude-fable-5-2 (reported by agent)");
  expect(rep).toHaveAttribute("title", expect.stringMatching(/unverified/));
  const a2 = screen.getByRole("button", { name: "Claude Code session A2" }).closest("li")!;
  expect(a2).toHaveTextContent("model not reported");
  const h1 = screen.getByRole("button", { name: "mystery-agent session H1" }).closest("li")!;
  expect(h1).toHaveTextContent("Human started");
  expect(h1).not.toHaveTextContent("reported");
  expect(screen.getAllByText(/Source and host are hints/)).toHaveLength(1);
  expect(within(screen.getByRole("list", { name: "Ended sessions" })).getByText("revoked", { selector: ".left" })).toBeInTheDocument();
  await userEvent.click(within(a1).getByRole("button", { name: "Claude Code session A1" }));
  expect(within(a1).getByText("/bin/claude · pid 1")).toBeInTheDocument();
  await go("Revoke Claude Code session A1");
  expect(m.revoke).toHaveBeenCalledWith("A1");
});

test("sessions: empty state", async () => {
  m.status.mockResolvedValue({ locked: false, leases: [] });
  render(<App />);
  await nav("Sessions");
  expect(await screen.findByText("No sessions yet.")).toBeInTheDocument();
});

test("overview and sessions: Claude mark, reported model chip, none for unreported human session", async () => {
  const soon = Math.floor(Date.now() / 1000) + 3000;
  const long = "claude-sonnet-5-5-with-a-very-long-suffix-for-ellipsis";
  m.status.mockResolvedValue({ locked: false, leases: [
    { ...lease, id: "A1", expires_at: soon, started_by: "agent", report: { agent: "claude-code", model: long, reported: true } },
    { ...lease, id: "H1", expires_at: soon, command: "cursor-agent", source: { kind: "cursor", label: "Cursor" } },
  ] });
  render(<App />);
  const a1 = await screen.findByRole("listitem", { name: "claude session A1" });
  expect(within(a1).getByRole("img", { name: "Claude" })).toBeInTheDocument();
  const chip = within(a1).getByText(`${long} (reported by agent)`);
  expect(chip).toHaveAttribute("title", expect.stringMatching(/unverified/));
  const h1 = screen.getByRole("listitem", { name: "cursor-agent session H1" });
  expect(within(h1).queryByRole("img", { name: "Claude" })).toBeNull();
  expect(h1).not.toHaveTextContent("reported");
  await nav("Sessions");
  const s1 = (await screen.findByRole("button", { name: "Claude Code session A1" })).closest("li")!;
  expect(within(s1).getByRole("img", { name: "Claude" })).toBeInTheDocument();
  expect(within(screen.getByRole("button", { name: "Cursor session H1" }).closest("li")!).queryByRole("img", { name: "Claude" })).toBeNull();
});
