import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { createClient } from "@locksmith/control-plane-client";
import { App } from "../App";
import { installFixtureFetch } from "../api/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});
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
  await userEvent.clear(input);
  await userEvent.type(input, "invoices");
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
  const agent = {
    id: "a1",
    name: "bot",
    description: "",
    created_at: "2026-11-20T00:00:00Z",
    updated_at: "2026-11-20T00:00:00Z",
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (u: string, i?: RequestInit) => {
      const path = new URL(String(u), "http://x").pathname;
      if (path === "/v1/agents")
        return new Response(JSON.stringify({ items: [agent], next: null }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      if (path === "/v1/agents/a1/grants")
        return new Response(JSON.stringify({ title: "Bad", detail: "down", status: 503 }), {
          status: 503,
          headers: { "content-type": "application/json" },
        });
      return base(u, i);
    }),
  );
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
  expect(
    screen.getByText(/Host: db\.internal\.example\.com · Port: 5432 · User: app · Database: appdb · TLS: verify-full/),
  ).toBeInTheDocument();
  expect(screen.getAllByText(/Header: Authorization/).length).toBeGreaterThan(0);
  expect(document.body.textContent).not.toMatch(/password/i);
  expect(r.requests).toContain("GET /v1/bindings");
});

test("bindings: an MCP row shows origin, header, default and each tool's decision, never a secret id", async () => {
  open("/bindings");
  const row = (await screen.findAllByText("github"))[0]!.closest("tr")!;
  expect(row).toHaveTextContent("MCP");
  expect(row).toHaveTextContent(
    "Upstream: https://api.githubcopilot.com/mcp/ · Header: Authorization · Other tools: hide · Allow: list_issues · Hold: create_issue · Deny: delete_repository",
  );
  expect(row.textContent).not.toMatch(/secret|template|token/i);
  expect(row.querySelector("input, button, a")).toBeNull();
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

test("bindings: AWS rows show role, region, vend and max duration (d2-aws-sts)", async () => {
  open("/bindings");
  const row = (await screen.findAllByText("arn:aws:iam::123456789012:role/deploy"))[0]!.closest("tr")!;
  expect(row).toHaveTextContent("AWS");
  expect(row).toHaveTextContent(
    "Role: arn:aws:iam::123456789012:role/deploy · Region: eu-west-1 · Vend credentials: yes · Max duration: 900s · Allowed actions: s3:GetObject, s3:PutObject",
  );
  expect(row.textContent).not.toMatch(/external|secret|token|AKIA/i);
});

test("bindings: a credential-shaped field injected into an AWS row never renders (d2-aws-sts 5.1)", async () => {
  installFixtureFetch();
  const client = createClient("o");
  const leaky = {
    kind: "aws" as const,
    name: "arn:aws:iam::1:role/dev",
    role: "arn:aws:iam::1:role/dev",
    region: "us-east-1",
    vend: true,
    max_duration_secs: 900,
    allowed_actions: ["s3:ListBucket"],
    secret_id: "SECRET-ID-VALUE",
    external_id: "EXT-VALUE",
    secret_access_key: "SAK-VALUE",
    session_token: "TOKEN-VALUE",
  };
  client.listBindings = async () => [leaky];
  const { container } = render(<App client={client} initialPath="/bindings" />);
  const row = (await screen.findAllByText("arn:aws:iam::1:role/dev"))[0]!.closest("tr")!;
  expect(row).toHaveTextContent("Allowed actions: s3:ListBucket");
  expect(container.textContent).not.toMatch(/SECRET-ID-VALUE|EXT-VALUE|SAK-VALUE|TOKEN-VALUE/);
});

test("notifications: bell shows unread, inbox marks read, empty state", async () => {
  open("/notifications");
  expect(await screen.findByTestId("unread-count")).toHaveTextContent("1");
  expect(await screen.findByText("Relay denied on stripe by ci-agent")).toBeInTheDocument();
  await userEvent.click(screen.getByText(/Mark read: Relay denied/));
  await waitFor(() => expect(screen.queryByTestId("unread-count")).toBeNull());
});

test("notifications: empty inbox and failed load with retry", async () => {
  open("/notifications", { empty: true });
  expect(await screen.findByText("No notifications.")).toBeInTheDocument();
});

test("notification settings: owner toggles a rule and email; a 403 hides the controls", async () => {
  const fx = open("/settings/notifications");
  await userEvent.click(await screen.findByLabelText("Git access denied to inbox"));
  await waitFor(() => expect(fx.requests).toContain("PUT /v1/notification-rules"));
  await userEvent.click(await screen.findByLabelText("Email delivery"));
  await waitFor(() => expect(fx.requests).toContain("PUT /v1/notification-channels"));
  expect(screen.getByText("Slack: not configured")).toBeInTheDocument();
});

test("notification settings: a failed email delivery shows a banner, otherwise none", async () => {
  open("/settings/notifications", { deliveryFailed: true });
  expect(await screen.findByText(/Email delivery failed/)).toBeInTheDocument();
});

test("notification settings: no banner when delivery is healthy", async () => {
  open("/settings/notifications");
  await screen.findByLabelText("Email delivery");
  expect(screen.queryByText(/Email delivery failed/)).toBeNull();
});

test("notification settings: non-owner sees a notice and no controls", async () => {
  open("/settings/notifications", { fail: { "GET /v1/notification-rules": 403 } });
  expect(await screen.findByText(/Only an organization owner/)).toBeInTheDocument();
  expect(screen.queryByLabelText("Email delivery")).toBeNull();
});
