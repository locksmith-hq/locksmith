import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { App } from "./App";
import { createClient } from "@locksmith/control-plane-client";

const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const tool = (layer: string, name: string, def: boolean, enabled: boolean) => ({ layer, tool: name, description: `${name} desc`, default_enabled: def, enabled, overridden: def !== enabled });
const cl = (id: string, name: string, revoked?: string) => ({ id, layer: "hub", client_id: `cid-${id}`, principal: "user-1", client_name: name, first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-02T00:00:00Z", revoked_at: revoked ?? null });

let tools: unknown[];
let clients: unknown[];
let status: number;
const fetchMock = vi.fn();

beforeEach(() => {
  tools = [tool("hub", "list_projects", true, true), tool("hub", "revoke_grant", false, false), tool("agent", "relay_http_request", true, true)];
  clients = [cl("c1", "Claude"), cl("c2", "", "2026-01-03T00:00:00Z")];
  status = 200;
  fetchMock.mockReset();
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const m = init?.method ?? "GET";
    if (url === "/v1/agents") return json({ items: [] });
    if (status !== 200 && url.startsWith("/v1/mcp")) return json({ title: "Forbidden" }, status);
    if (m === "GET" && url === "/v1/mcp/tools") return json({ items: tools });
    if (m === "PUT" && url.startsWith("/v1/mcp/tools/")) {
      const [, , , , layer, name] = url.split("/");
      return json(tool(layer!, decodeURIComponent(name!), false, JSON.parse(init!.body as string).enabled));
    }
    if (m === "GET" && url === "/v1/mcp/clients") return json({ items: clients });
    if (m === "POST" && url === "/v1/mcp/clients/c1/revoke") return json(cl("c1", "Claude", "2026-01-04T00:00:00Z"));
    return json({ title: "nope" }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

const open = async (page: string) => {
  render(<App client={createClient("org1")} />);
  await userEvent.click(await screen.findByRole("button", { name: page }));
};

test("tools page groups one switch per tool by layer and saves a change", async () => {
  await open("Tools");
  const sw = await screen.findByRole("switch", { name: "revoke_grant (hub)" });
  expect(sw).not.toBeChecked();
  expect(screen.getByRole("switch", { name: "relay_http_request (agent)" })).toBeChecked();
  await userEvent.click(sw);
  await waitFor(() => expect(screen.getByRole("switch", { name: "revoke_grant (hub)" })).toBeChecked());
  const put = fetchMock.mock.calls.find((c) => c[1]?.method === "PUT")!;
  expect(put[0]).toBe("/v1/mcp/tools/hub/revoke_grant");
  expect(JSON.parse(put[1].body)).toEqual({ enabled: true });
});

test("tools page shows an error and keeps the switch when saving is refused", async () => {
  await open("Tools");
  const sw = await screen.findByRole("switch", { name: "revoke_grant (hub)" });
  fetchMock.mockImplementationOnce(async () => json({ title: "Forbidden" }, 403));
  await userEvent.click(sw);
  expect(await screen.findByRole("alert")).toBeInTheDocument();
  expect(screen.getByRole("switch", { name: "revoke_grant (hub)" })).not.toBeChecked();
});

test("tools page shows 403 and empty states", async () => {
  status = 403;
  await open("Tools");
  expect(await screen.findByRole("alert")).toHaveTextContent(/Forbidden|403/);
  expect(screen.queryByRole("switch")).toBeNull();
});

test("tools page empty state", async () => {
  tools = [];
  await open("Tools");
  expect(await screen.findByText("No MCP tools.")).toBeInTheDocument();
});

test("clients page lists clients and revokes an active one", async () => {
  await open("Clients");
  expect(await screen.findByText("Claude")).toBeInTheDocument();
  expect(screen.getByText(/Revoked 2026-01-03/)).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: /^Revoke / })).toHaveLength(1);
  await userEvent.click(screen.getByRole("button", { name: "Revoke Claude" }));
  expect(await screen.findByText(/Revoked 2026-01-04/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /^Revoke / })).toBeNull();
});

test("clients page shows 403 and empty states", async () => {
  status = 403;
  await open("Clients");
  expect(await screen.findByRole("alert")).toBeInTheDocument();
});

test("clients page empty state", async () => {
  clients = [];
  await open("Clients");
  expect(await screen.findByText(/No MCP clients have signed in yet/)).toBeInTheDocument();
});
