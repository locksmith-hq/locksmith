import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { createClient } from "@locksmith/control-plane-client";
import { App } from "../App";
import { installFixtureFetch } from "../api/fixtures";

afterEach(() => { vi.unstubAllGlobals(); localStorage.clear(); });
const open = (path: string, opts?: Parameters<typeof installFixtureFetch>[0]) => {
  const fx = installFixtureFetch(opts);
  render(<App client={createClient("o")} initialPath={path} />);
  return fx;
};

test("overview shows counts, recent activity empty state and a dismissible checklist", async () => {
  open("/overview");
  expect(await screen.findByTestId("count-projects")).toHaveTextContent("Projects: 1");
  expect(await screen.findByText("No activity yet.")).toBeInTheDocument();
  await userEvent.click(screen.getByText("Dismiss"));
  expect(screen.queryByRole("region", { name: "Get started" })).toBeNull();
  expect(localStorage.getItem("ls-get-started-dismissed")).toBe("1");
});

test("projects: create, rename, delete with confirm", async () => {
  const fx = open("/projects");
  expect(await screen.findByText("payments")).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("project name"), "billing");
  await userEvent.click(screen.getByText("Create project"));
  expect(await screen.findByText("billing")).toBeInTheDocument();
  await userEvent.click(screen.getByText("Rename billing"));
  const input = screen.getByLabelText("New name for billing");
  await userEvent.clear(input); await userEvent.type(input, "invoices");
  await userEvent.click(screen.getByText("Save"));
  expect(await screen.findByText("invoices")).toBeInTheDocument();
  await userEvent.click(screen.getByText("Delete invoices"));
  expect(fx.requests.some((r) => r.startsWith("DELETE"))).toBe(false);
  await userEvent.click(screen.getByText("Confirm delete"));
  await waitFor(() => expect(screen.queryByText("invoices")).toBeNull());
});

test("projects: 409 on duplicate name shows the problem and leaves the list unchanged", async () => {
  open("/projects");
  await screen.findByText("payments");
  await userEvent.type(screen.getByLabelText("project name"), "payments");
  await userEvent.click(screen.getByText("Create project"));
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toMatch(/status 409|fixture 409/);
  expect(screen.getAllByText("payments")).toHaveLength(1);
});

test("projects: 403 list shows an error with retry, not the empty message", async () => {
  open("/projects", { fail: { "GET /v1/projects": 403 } });
  expect(await screen.findByRole("alert")).toBeInTheDocument();
  expect(screen.getByText("Retry")).toBeInTheDocument();
  expect(screen.queryByText("No projects yet.")).toBeNull();
});

test("projects: empty", async () => {
  open("/projects", { empty: true });
  expect(await screen.findByText("No projects yet.")).toBeInTheDocument();
});

test("environments: list, create, delete inside a project", async () => {
  open("/projects/00000000-0000-4000-8000-000000000001");
  expect(await screen.findByText("dev")).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("environment name"), "prod");
  await userEvent.click(screen.getByText("Create environment"));
  expect(await screen.findByText("prod")).toBeInTheDocument();
  await userEvent.click(screen.getByText("Delete prod"));
  await userEvent.click(screen.getByText("Confirm delete"));
  await waitFor(() => expect(screen.queryByText("prod")).toBeNull());
});

test("secrets: list and detail with versions never request a value or material route", async () => {
  const fx = open("/secrets");
  expect(await screen.findByText("STRIPE_KEY")).toBeInTheDocument();
  await userEvent.click(screen.getByText("STRIPE_KEY"));
  expect((await screen.findAllByText("gateway:v1", { selector: "td" })).length).toBe(2);
  expect(fx.requests.length).toBeGreaterThan(0);
  expect(fx.requests.filter((r) => /value|material|reveal/i.test(r))).toEqual([]);
});

test("agents: a 5xx list shows an error with retry, not the empty message", async () => {
  open("/agents", { fail: { "GET /v1/agents": 503 } });
  expect(await screen.findByRole("alert")).toBeInTheDocument();
  expect(screen.getByText("Retry")).toBeInTheDocument();
  expect(screen.queryByText("No agents yet.")).toBeNull();
});

test("grants: a 5xx grants list shows an error with retry, not the empty message", async () => {
  installFixtureFetch();
  const base = fetch as unknown as (u: string, i?: RequestInit) => Promise<Response>;
  const agent = { id: "a1", name: "bot", description: "", created_at: "2026-11-20T00:00:00Z", updated_at: "2026-11-20T00:00:00Z" };
  vi.stubGlobal("fetch", vi.fn(async (u: string, i?: RequestInit) => {
    const path = new URL(String(u), "http://x").pathname;
    if (path === "/v1/agents") return new Response(JSON.stringify({ items: [agent], next: null }), { status: 200, headers: { "content-type": "application/json" } });
    if (path === "/v1/agents/a1/grants") return new Response(JSON.stringify({ title: "Bad", detail: "down", status: 503 }), { status: 503, headers: { "content-type": "application/json" } });
    return base(u, i);
  }));
  render(<App client={createClient("o")} initialPath="/grants" />);
  expect(await screen.findByText("down")).toBeInTheDocument();
  expect(screen.getByText("Retry")).toBeInTheDocument();
  expect(screen.queryByText("No grants yet.")).toBeNull();
});

test("activity: a 5xx ledger read shows an error with retry and no empty message", async () => {
  open("/activity", { fail: { "GET /v1/audit/events": 503 } });
  expect(await screen.findByRole("alert")).toBeInTheDocument();
  expect(screen.getByText("Retry")).toBeInTheDocument();
  expect(screen.queryByText("No audit events yet.")).toBeNull();
  expect(screen.queryByText("Reading the ledger…")).toBeNull();
});

test("bindings: lists non-secret fields per kind, never a password, and shows the empty state", async () => {
  const r = open("/bindings");
  expect(await screen.findByText("appdb")).toBeInTheDocument();
  expect(screen.getByText(/Host: db\.internal\.example\.com · Port: 5432 · User: app · Database: appdb · TLS: verify-full/)).toBeInTheDocument();
  expect(screen.getByText(/Header: Authorization/)).toBeInTheDocument();
  expect(document.body.textContent).not.toMatch(/password/i);
  expect(r.requests).toContain("GET /v1/bindings");
});

test("bindings: empty list and a 5xx show honest states", async () => {
  open("/bindings", { empty: true });
  expect(await screen.findByText("The gateway has not published any bindings yet.")).toBeInTheDocument();
});

test("bindings: a 5xx shows an error with retry, not the empty message", async () => {
  open("/bindings", { fail: { "GET /v1/bindings": 503 } });
  expect(await screen.findByRole("alert")).toBeInTheDocument();
  expect(screen.queryByText("The gateway has not published any bindings yet.")).toBeNull();
});
