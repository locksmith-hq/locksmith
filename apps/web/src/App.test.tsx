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

const mk = () => render(<App client={createClient("org1")} />);

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
