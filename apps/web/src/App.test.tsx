import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { App } from "./App";
import { createClient } from "@locksmith/control-plane-client";

const ID = "11111111-1111-4111-8111-111111111111";
const SID = "22222222-2222-4222-8222-222222222222";
const agent = { id: ID, name: "bot", description: "ci", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" };
const grant = { id: "g1", agent_id: ID, secret_id: SID, secret_name: "GITHUB_TOKEN", mode: "relay" as const, created_at: "2026-01-01T00:00:00Z", expires_at: null };
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });

const auditEv = (seq: number, kind: string) => ({ id: `e${seq}`, seq, at: "2026-01-01T00:00:00Z", kind, actor: "agent:a1", target: "secret:s1", outcome: "ok", attrs: { leak: "ATTRSENTINEL" }, digest: "d", prev_digest: "p" });

let agents: unknown[];
let grants: unknown[];
const fetchMock = vi.fn();

beforeEach(() => {
  agents = [agent]; grants = [grant];
  fetchMock.mockReset();
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const m = init?.method ?? "GET";
    if (m === "GET" && url === "/v1/agents") return json({ items: agents });
    if (m === "GET" && url.endsWith("/grants")) return json({ items: grants });
    if (m === "GET" && url === "/v1/audit/status") {
      return json({ head_seq: 3, latest_checkpoint: { seq: 2, at: "2026-01-02T00:00:00Z", digest: "ab", key_id: "audit-checkpoint:1" },
        latest_verify: { ok: true, finished_at: "2026-01-03T00:00:00Z", started_at: "2026-01-03T00:00:00Z", id: "v", mode: "db", events: 3, checkpoints: 1 } });
    }
    if (m === "GET" && url === "/v1/audit/events") return json({ items: [auditEv(3, "relay.outcome")], next: "c1" });
    if (m === "GET" && url === "/v1/audit/events?cursor=c1") return json({ items: [auditEv(2, "agent.created")] });
    if (m === "POST" && url === "/v1/agents") {
      agents = [agent];
      return json({ agent, enrollment_secret: "lse_SUPERSECRET" }, 201);
    }
    if (m === "POST" && url.endsWith("/grants")) return json(grant, 201);
    if (m === "DELETE") { if (url.includes("/grants/")) grants = []; else agents = []; return new Response(null, { status: 204 }); }
    return json({ title: "nope" }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  localStorage.clear();
});
afterEach(() => vi.unstubAllGlobals());

const mk = (path = "/agents") => render(<App client={createClient("org1")} initialPath={path} />);

test("lists agents and grants, sending the org header", async () => {
  mk();
  expect(await screen.findByText("bot")).toBeInTheDocument();
  expect(await screen.findByText(/\(relay\)/)).toBeInTheDocument();
  expect(fetchMock.mock.calls[0]![1].headers["x-locksmith-dev-org"]).toBe("org1");
});

test("create shows the enrollment secret once and never persists it", async () => {
  const setItem = vi.spyOn(Storage.prototype, "setItem");
  const log = vi.spyOn(console, "log");
  mk();
  await screen.findByText("bot");
  await userEvent.type(screen.getByLabelText("Agent name"), "bot");
  await userEvent.click(screen.getByText("Create agent"));
  expect(await screen.findByTestId("enrollment-secret")).toHaveTextContent("lse_SUPERSECRET");
  expect(JSON.parse(fetchMock.mock.calls.find((c) => c[1]?.method === "POST")![1].body)).toEqual({ name: "bot", description: "" });
  await userEvent.click(screen.getByText("Dismiss"));
  expect(screen.queryByText(/lse_SUPERSECRET/)).toBeNull();
  expect(JSON.stringify(setItem.mock.calls)).not.toContain("SUPERSECRET");
  expect(JSON.stringify(Object.entries(localStorage))).not.toContain("SUPERSECRET");
  expect(JSON.stringify(log.mock.calls)).not.toContain("SUPERSECRET");
});

test("delete agent calls DELETE and refreshes", async () => {
  mk();
  await userEvent.click(await screen.findByText("Delete bot"));
  await waitFor(() => expect(screen.getByText("No agents yet.")).toBeInTheDocument());
  expect(fetchMock).toHaveBeenCalledWith(`/v1/agents/${ID}`, expect.objectContaining({ method: "DELETE" }));
});

test("create and revoke grant", async () => {
  mk();
  await screen.findByText(/\(relay\)/);
  await userEvent.type(screen.getByLabelText("Secret id for bot"), SID);
  await userEvent.click(screen.getByText("Grant bot"));
  await waitFor(() => {
    const c = fetchMock.mock.calls.find((c) => c[1]?.method === "POST" && c[0].endsWith("/grants"))!;
    expect(JSON.parse(c[1].body)).toEqual({ secret_id: SID, mode: "relay", expires_at: null });
  });
  await userEvent.click(screen.getByText("Revoke GITHUB_TOKEN"));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/agents/${ID}/grants/g1`, expect.objectContaining({ method: "DELETE" })));
});

test("shows problem detail on error", async () => {
  fetchMock.mockImplementation(async () => json({ title: "Bad", detail: "boom" }, 503));
  mk();
  expect(await screen.findByRole("alert")).toHaveTextContent("boom");
});

test("audit page shows chain status, events, and pages on demand", async () => {
  mk();
  await userEvent.click(screen.getByRole("link", { name: "Activity" }));
  expect(await screen.findByText("relay.outcome")).toBeInTheDocument();
  expect(screen.getByText(/seq 2 at/)).toBeInTheDocument();
  expect(screen.getByTestId("verify-result")).toHaveTextContent("Verified OK");
  await userEvent.click(screen.getByText("Load more"));
  expect(await screen.findByText("agent.created")).toBeInTheDocument();
  expect(screen.queryByText("Load more")).toBeNull();
});

test("audit page never renders attrs, shows a failed verify, and surfaces load errors", async () => {
  fetchMock.mockImplementation(async (url: string) => {
    if (url === "/v1/audit/status") return json({ head_seq: 1, latest_checkpoint: null, latest_verify: { ok: false, finished_at: "t2", broken_seq: 2, break_kind: "hash" } });
    return json({ title: "Bad", detail: "ledger down" }, 503);
  });
  mk();
  await userEvent.click(screen.getByRole("link", { name: "Activity" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("ledger down");
  expect(await screen.findByTestId("verify-result")).toHaveTextContent("FAILED at t2 (first broken seq 2, hash)");
  expect(screen.getByText(/none yet/)).toBeInTheDocument();
  expect(screen.queryByText("No audit events yet.")).toBeNull();
  expect(document.body.textContent).not.toContain("ATTRSENTINEL");
});

test("audit load more cannot double-append on a double click", async () => {
  mk();
  await userEvent.click(screen.getByRole("link", { name: "Activity" }));
  const btn = await screen.findByText("Load more");
  btn.click(); btn.click();
  expect(await screen.findByText("agent.created")).toBeInTheDocument();
  expect(fetchMock.mock.calls.filter((c) => c[0] === "/v1/audit/events?cursor=c1")).toHaveLength(1);
  expect(screen.getAllByText("agent.created")).toHaveLength(1);
});

test("audit outcome filter narrows to denied and redaction_failed events", async () => {
  const ev = (seq: number, kind: string, outcome: string) => ({ ...auditEv(seq, kind), outcome });
  fetchMock.mockImplementation(async (url: string) => {
    if (url === "/v1/audit/status") return json({ head_seq: 3, latest_checkpoint: null, latest_verify: null });
    return json({ items: [ev(3, "relay.outcome", "redaction_failed"), ev(2, "relay.denied", "no_grant"), ev(1, "agent.created", "ok")] });
  });
  mk();
  await userEvent.click(screen.getByRole("link", { name: "Activity" }));
  expect(await screen.findByText("agent.created")).toBeInTheDocument();
  const sel = screen.getByRole("combobox", { name: "Outcome filter" });
  await userEvent.selectOptions(sel, "denied");
  expect(screen.getByText("relay.denied")).toBeInTheDocument();
  expect(screen.queryByText("agent.created")).toBeNull();
  expect(screen.queryByText("relay.outcome")).toBeNull();
  await userEvent.selectOptions(sel, "redaction_failed");
  expect(screen.getByText("relay.outcome")).toBeInTheDocument();
  expect(screen.queryByText("relay.denied")).toBeNull();
  await userEvent.selectOptions(sel, "all");
  expect(screen.getByText("agent.created")).toBeInTheDocument();
});
